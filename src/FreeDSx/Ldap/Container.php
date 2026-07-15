<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap;

use Closure;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\Factory\ClientProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ClientQueueInstantiator;
use FreeDSx\Ldap\Protocol\RootDseLoader;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\Clock\ClockInterface;
use FreeDSx\Ldap\Server\Clock\SystemClock;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\ReplicaPasswordStateStoreProviderInterface;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\CoroutineSleeper;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\Forward\LdapClientForwardStateSender;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\Forward\PasswordPolicyForwardWorker;
use FreeDSx\Ldap\Server\Process\BackgroundTask\LongLivedTask;
use FreeDSx\Ldap\Server\Process\BackgroundTask\PcntlBackgroundTasks;
use FreeDSx\Ldap\Server\Process\BackgroundTask\PeriodicTask;
use FreeDSx\Ldap\Server\Process\BackgroundTask\SwooleBackgroundTasks;
use FreeDSx\Ldap\Server\Process\Signals\PcntlShutdownSignals;
use FreeDSx\Ldap\Sync\Consumer\LdapReplica;
use FreeDSx\Ldap\Sync\Consumer\PrimaryConnectionFactory;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeRecorder;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionPolicy;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionSweeper;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Backend\Storage\OperationalAttributeGenerator;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use Psr\Log\NullLogger;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\Metrics\File\FileSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\File\FileSnapshotWriter;
use FreeDSx\Ldap\Server\Metrics\File\SnapshotPublisher;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\MetricsSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Recorder\MetricsRecorderChain;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Rollup\OperationRollupCoordinator;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\AllowUserChangeConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\HistoryConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\MinAgeConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\QualityConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\SafeModifyConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyComponentFactory;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\UniquePolicyTimeFactory;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\InMemoryReplicaPasswordStateStore;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyTargetResolver;
use FreeDSx\Ldap\Server\RequestHandler\HandlerFactory;
use FreeDSx\Ldap\Server\Proxy\ProxyProtocolFactory;
use FreeDSx\Ldap\Server\ServerProtocolFactory;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\Server\ServerRunner\PcntlServerRunner;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\Server\ServerRunner\SwooleServerRunner;
use FreeDSx\Ldap\Server\SocketServerFactory;
use FreeDSx\Socket\SocketOptions;
use FreeDSx\Socket\SocketPool;
use FreeDSx\Socket\SocketPoolOptions;
use FreeDSx\Socket\Transport;

class Container
{
    /**
     * These are classes that should never cache an instance when retrieved from the container.
     */
    private const FACTORY_ONLY = [
        HandlerFactoryInterface::class,
        ServerAuthorization::class,
    ];

    /**
     * @var array<class-string, callable>
     */
    private array $instanceFactory = [];

    /**
     * @var array<class-string, object>
     */
    private array $instances = [];

    /**
     * @param array<class-string, object> $instances
     */
    public function __construct(array $instances)
    {
        foreach ($instances as $className => $instance) {
            $this->instances[$className] = $instance;
        }

        $this->registerClientClasses();
        $this->registerServerClasses();
    }

    /**
     * @template T of object
     * @param class-string<T> $className
     * @return T
     */
    public function get(string $className): object
    {
        if (isset($this->instances[$className]) && $this->instances[$className] instanceof $className) {
            return $this->instances[$className];
        }

        if (!isset($this->instanceFactory[$className])) {
            throw new RuntimeException(sprintf(
                'The class "%s" is not recognized.',
                $className,
            ));
        }

        $instance = ($this->instanceFactory[$className])();
        if (!$instance instanceof $className) {
            throw new RuntimeException(sprintf(
                'The factory for "%s" did not return the expected type.',
                $className,
            ));
        }

        if (!in_array($className, self::FACTORY_ONLY, true)) {
            $this->instances[$className] = $instance;
        }

        return $instance;
    }

    /**
     * @param class-string $className
     */
    public function has(string $className): bool
    {
        return isset($this->instances[$className])
            || isset($this->instanceFactory[$className]);
    }

    /**
     * @param class-string $className
     */
    private function registerFactory(
        string $className,
        callable $factory,
    ): void {
        $this->instanceFactory[$className] = $factory;
    }

    private function registerClientClasses(): void
    {
        if (!isset($this->instances[ClientOptions::class])) {
            return;
        }

        $this->registerFactory(
            className: ClientProtocolHandler::class,
            factory: $this->makeClientProtocolHandler(...),
        );
        $this->registerFactory(
            className: SocketPool::class,
            factory: $this->makeSocketPool(...),
        );
        $this->registerFactory(
            className: ClientProtocolHandlerFactory::class,
            factory: $this->makeClientProtocolHandlerFactory(...),
        );
        $this->registerFactory(
            className: ClientQueueInstantiator::class,
            factory: $this->makeClientQueueInstantiator(...),
        );
        $this->registerFactory(
            className: RootDseLoader::class,
            factory: $this->makeRootDseLoader(...),
        );
    }

    private function registerServerClasses(): void
    {
        if (!isset($this->instances[ServerOptions::class])) {
            return;
        }

        $this->registerFactory(
            className: SocketServerFactory::class,
            factory: $this->makeSocketServerFactory(...),
        );
        $this->registerFactory(
            className: HandlerFactoryInterface::class,
            factory: $this->makeHandlerFactory(...),
        );
        $this->registerFactory(
            className: WritableStorageBackend::class,
            factory: $this->makeBackend(...),
        );
        $this->registerFactory(
            className: ServerProtocolFactory::class,
            factory: $this->makeServerProtocolFactory(...),
        );
        $this->registerFactory(
            className: ServerProtocolFactoryInterface::class,
            factory: $this->makeServerProtocolFactoryInterface(...),
        );
        $this->registerFactory(
            className: ServerRunnerInterface::class,
            factory: $this->makeServerRunner(...),
        );
        $this->registerFactory(
            className: ServerAuthorization::class,
            factory: $this->makeServerAuthorizer(...),
        );
        $this->registerFactory(
            className: ClockInterface::class,
            factory: static fn(): ClockInterface => new SystemClock(),
        );
        $this->registerFactory(
            className: PasswordPolicyEngine::class,
            factory: $this->makePasswordPolicyEngine(...),
        );
        $this->registerFactory(
            className: ReplicaPasswordStateStoreInterface::class,
            factory: $this->makeReplicaPasswordStateStore(...),
        );
        $this->registerFactory(
            className: ServerProtocolHandlerFactory::class,
            factory: $this->makeServerProtocolHandlerFactory(...),
        );
        $this->registerFactory(
            className: PasswordModifyTargetResolver::class,
            factory: $this->makePasswordModifyTargetResolver(...),
        );
        $this->registerFactory(
            className: PasswordHashService::class,
            factory: $this->makePasswordHashService(...),
        );
        $this->registerFactory(
            className: WriteOperationDispatcher::class,
            factory: $this->makeWriteOperationDispatcher(...),
        );
        $this->registerFactory(
            className: PasswordPolicyComponentFactory::class,
            factory: $this->makePasswordPolicyComponentFactory(...),
        );
        $this->registerFactory(
            className: InMemoryMetricsRecorder::class,
            factory: static fn(): InMemoryMetricsRecorder => new InMemoryMetricsRecorder(),
        );
        $this->registerFactory(
            className: MetricsRecorderInterface::class,
            factory: $this->makeMetricsRecorder(...),
        );
        $this->registerFactory(
            className: MetricsSnapshotProvider::class,
            factory: $this->makeMetricsSnapshotProvider(...),
        );
        $this->registerFactory(
            className: OperationRollupCoordinator::class,
            factory: fn(): OperationRollupCoordinator => new OperationRollupCoordinator(
                $this->get(InMemoryMetricsRecorder::class),
            ),
        );
    }

    /**
     * The process metrics recorder: an in-memory recorder when cn=monitor is enabled (chained with a user recorder if
     * set), otherwise just the user recorder (a no-op by default).
     */
    private function makeMetricsRecorder(): MetricsRecorderInterface
    {
        $options = $this->get(ServerOptions::class);
        $userRecorder = $options->getMetricsRecorder();

        if (!$options->isMonitorEnabled()) {
            return $userRecorder;
        }

        $inMemory = $this->get(InMemoryMetricsRecorder::class);

        if ($userRecorder instanceof NullMetricsRecorder) {
            return $inMemory;
        }

        return new MetricsRecorderChain(
            $inMemory,
            $userRecorder,
        );
    }

    /**
     * The snapshot source for cn=monitor: the live in-memory recorder under Swoole, or the parent-published file under
     * the forking PCNTL runner.
     */
    private function makeMetricsSnapshotProvider(): MetricsSnapshotProvider
    {
        $options = $this->get(ServerOptions::class);

        if (!$options->getUseSwooleRunner()) {
            return new FileSnapshotProvider($this->monitorSnapshotPath($options));
        }

        return $this->get(InMemoryMetricsRecorder::class);
    }

    private function monitorSnapshotPath(ServerOptions $options): string
    {
        return $options->getMonitorSnapshotPath()
            ?? sys_get_temp_dir() . '/freedsx_ldap_monitor_' . $options->getPort() . '.json';
    }

    private function makePasswordPolicyEngine(): PasswordPolicyEngine
    {
        $options = $this->get(ServerOptions::class);
        $clock = $this->get(ClockInterface::class);

        $chain = new PasswordChangeConstraintChain([
            new AllowUserChangeConstraint(),
            new SafeModifyConstraint(),
            new MinAgeConstraint($clock),
            new QualityConstraint($options->getPasswordQualityChecker()),
            new HistoryConstraint(new PasswordHashService()),
        ]);

        return new PasswordPolicyEngine(
            clock: $clock,
            changeConstraints: $chain,
            uniqueTimes: new UniquePolicyTimeFactory(
                $clock,
                $options->getChangeJournalConfig()->origin,
            ),
        );
    }

    private function makeClientProtocolHandler(): ClientProtocolHandler
    {
        return new ClientProtocolHandler(
            options: $this->get(ClientOptions::class),
            clientQueueInstantiator: $this->get(ClientQueueInstantiator::class),
            protocolHandlerFactory: $this->get(ClientProtocolHandlerFactory::class),
        );
    }

    private function makeClientQueueInstantiator(): ClientQueueInstantiator
    {
        return new ClientQueueInstantiator($this->get(SocketPool::class));
    }

    private function makeSocketPool(): SocketPool
    {
        $clientOptions = $this->get(ClientOptions::class);
        $socketOptions = (new SocketOptions())
            ->setTransport(Transport::from($clientOptions->getTransport()))
            ->setPort($clientOptions->getPort())
            ->setUseSsl($clientOptions->isUseSsl())
            ->setSslValidateCert($clientOptions->isSslValidateCert())
            ->setSslAllowSelfSigned($clientOptions->isSslAllowSelfSigned())
            ->setSslCaCert($clientOptions->getSslCaCert())
            ->setSslCert($clientOptions->getSslCert())
            ->setSslCertKey($clientOptions->getSslCertKey())
            ->setSslPeerName($clientOptions->getSslPeerName())
            ->setTimeoutConnect($clientOptions->getTimeoutConnect())
            ->setTimeoutRead($clientOptions->getTimeoutRead());

        $poolOptions = (new SocketPoolOptions($socketOptions))
            ->setServers($clientOptions->getServers());

        return new SocketPool($poolOptions);
    }

    private function makeClientProtocolHandlerFactory(): ClientProtocolHandlerFactory
    {
        return new ClientProtocolHandlerFactory(
            clientOptions: $this->get(ClientOptions::class),
            queueInstantiator: $this->get(ClientQueueInstantiator::class),
            rootDseLoader: $this->get(RootDseLoader::class),
        );
    }

    private function makeRootDseLoader(): RootDseLoader
    {
        return new RootDseLoader($this->get(LdapClient::class));
    }

    private function makeServerProtocolFactory(): ServerProtocolFactory
    {
        return new ServerProtocolFactory(
            handlerFactory: $this->get(HandlerFactoryInterface::class),
            options: $this->get(ServerOptions::class),
            passwordPolicyEngine: $this->get(PasswordPolicyEngine::class),
            routeResolver: $this->get(ServerProtocolHandlerFactory::class),
            targetResolver: $this->get(PasswordModifyTargetResolver::class),
            hashService: $this->get(PasswordHashService::class),
            writeDispatcher: $this->get(WriteOperationDispatcher::class),
            policyComponentFactory: $this->get(PasswordPolicyComponentFactory::class),
            metricsRecorder: $this->get(MetricsRecorderInterface::class),
            metricsSnapshots: $this->get(MetricsSnapshotProvider::class),
            operationRollup: $this->makeOperationRollup(),
            replicaPasswordStateStore: $this->get(ServerOptions::class)->isReadOnly()
                ? $this->get(ReplicaPasswordStateStoreInterface::class)
                : null,
        );
    }

    /**
     * The replica-local password-policy state store, persisted by the storage backend when it can, else in memory.
     */
    private function makeReplicaPasswordStateStore(): ReplicaPasswordStateStoreInterface
    {
        $storage = $this->get(ServerOptions::class)->getStorage();

        return $storage instanceof ReplicaPasswordStateStoreProviderInterface
            ? $storage->replicaPasswordStateStore()
            : new InMemoryReplicaPasswordStateStore();
    }

    private function makeServerProtocolFactoryInterface(): ServerProtocolFactoryInterface
    {
        if ($this->has(ProxyOptions::class)) {
            return new ProxyProtocolFactory(
                $this->get(ServerOptions::class),
                $this->get(ProxyOptions::class),
            );
        }

        return $this->get(ServerProtocolFactory::class);
    }

    private function makeServerProtocolHandlerFactory(): ServerProtocolHandlerFactory
    {
        return new ServerProtocolHandlerFactory($this->get(ServerOptions::class));
    }

    private function makePasswordModifyTargetResolver(): PasswordModifyTargetResolver
    {
        $handlerFactory = $this->get(HandlerFactoryInterface::class);

        return new PasswordModifyTargetResolver(
            $handlerFactory->makeBackend(),
            $handlerFactory->makeIdentityResolverChain(),
        );
    }

    private function makePasswordHashService(): PasswordHashService
    {
        return new PasswordHashService($this->get(ServerOptions::class)->getPasswordHashScheme());
    }

    private function makeWriteOperationDispatcher(): WriteOperationDispatcher
    {
        return $this->get(HandlerFactoryInterface::class)->makeWriteDispatcher();
    }

    private function makePasswordPolicyComponentFactory(): PasswordPolicyComponentFactory
    {
        return new PasswordPolicyComponentFactory(
            handlerFactory: $this->get(HandlerFactoryInterface::class),
            options: $this->get(ServerOptions::class),
            writeDispatcher: $this->get(WriteOperationDispatcher::class),
            passwordPolicyEngine: $this->get(PasswordPolicyEngine::class),
        );
    }

    private function makeHandlerFactory(): HandlerFactory
    {
        return new HandlerFactory(
            $this->get(ServerOptions::class),
            $this->backendOrFail(),
        );
    }

    /**
     * The configured backend; only reached on the non-proxy path, where LdapServer's startup check guarantees one.
     */
    private function backendOrFail(): WritableStorageBackend
    {
        return $this->backendOrNull()
            ?? throw new RuntimeException('No storage is configured; set ServerOptions::setStorage().');
    }

    /**
     * The configured backend, or null when no storage is set (the proxy path has none).
     */
    private function backendOrNull(): ?WritableStorageBackend
    {
        return $this->get(ServerOptions::class)->getStorage() !== null
            ? $this->get(WritableStorageBackend::class)
            : null;
    }

    /**
     * Assemble the writable backend from the configured storage; only invoked when storage is set.
     */
    private function makeBackend(): WritableStorageBackend
    {
        $options = $this->get(ServerOptions::class);
        $storage = $options->getStorage();

        if ($storage === null) {
            throw new RuntimeException('No storage is configured; set ServerOptions::setStorage().');
        }

        $schema = $options->getSchemaValidationMode() !== SchemaValidationMode::Off
            ? $options->getSchema()
            : null;

        return new WritableStorageBackend(
            storage: $storage,
            limits: $options->makeSearchLimits(),
            validator: $this->buildSchemaValidator(),
            operationalAttrs: new OperationalAttributeGenerator($schema),
            changeRecorder: $this->changeRecorderFor($storage),
            schema: $options->getSchema(),
        );
    }

    private function buildSchemaValidator(): ?SchemaValidator
    {
        $options = $this->get(ServerOptions::class);
        $mode = $options->getSchemaValidationMode();

        if ($mode === SchemaValidationMode::Off) {
            return null;
        }

        return new SchemaValidator(
            $options->getSchema(),
            $mode,
        );
    }

    /**
     * Configure the storage's journal and return a recorder when sync is enabled and the storage can journal.
     */
    private function changeRecorderFor(EntryStorageInterface $storage): ?ChangeRecorder
    {
        $options = $this->get(ServerOptions::class);

        if (!$options->isSyncEnabled() || !$storage instanceof ChangeJournalingInterface) {
            return null;
        }

        $storage->configureJournal($options->getChangeJournalConfig());

        return new ChangeRecorder($options->getLogger() ?? new NullLogger());
    }

    private function makeServerRunner(): ServerRunnerInterface
    {
        $options = $this->get(ServerOptions::class);
        $protocolFactoryProvider = $this->makeProtocolFactoryProvider();
        $metricsRecorder = $this->get(MetricsRecorderInterface::class);

        if ($options->getUseSwooleRunner()) {
            return new SwooleServerRunner(
                serverProtocolFactory: $protocolFactoryProvider($options),
                options: $options,
                socketServerFactory: $this->get(SocketServerFactory::class),
                protocolFactoryProvider: $protocolFactoryProvider,
                metricsRecorder: $metricsRecorder,
                backgroundTasks: $this->makeSwooleBackgroundTasks(),
            );
        }

        return new PcntlServerRunner(
            serverProtocolFactory: $protocolFactoryProvider($options),
            options: $options,
            socketServerFactory: $this->get(SocketServerFactory::class),
            protocolFactoryProvider: $protocolFactoryProvider,
            metricsRecorder: $metricsRecorder,
            snapshotPublisher: $this->makeSnapshotPublisher(),
            operationRollup: $this->makeOperationRollup(),
            backend: $this->backendOrNull(),
            backgroundTasks: $this->makePcntlBackgroundTasks(),
        );
    }

    /**
     * The retention policy to sweep on, or null when journaling is off / has no limits.
     */
    private function journalRetentionPolicyIfSweepable(): ?RetentionPolicy
    {
        $options = $this->get(ServerOptions::class);
        $backend = $this->backendOrNull();

        if ($backend === null || !$options->isSyncEnabled()) {
            return null;
        }

        $journal = $backend->changeJournal();

        if ($journal === null) {
            return null;
        }

        $policy = $options->getChangeJournalConfig()->retention;

        return RetentionSweeper::isSweepable(
            $policy,
            $journal,
            $options->getUseSwooleRunner(),
        )
            ? $policy
            : null;
    }

    private function makeRetentionSweeper(): ?RetentionSweeper
    {
        $policy = $this->journalRetentionPolicyIfSweepable();

        if ($policy === null) {
            return null;
        }

        // Safe to resolve now: a non-null policy means sync is enabled and the journal is configured.
        $journal = $this->backendOrNull()?->changeJournal();

        if ($journal === null) {
            return null;
        }

        $options = $this->get(ServerOptions::class);

        return new RetentionSweeper(
            $journal,
            $policy,
            new EventLogger(
                $options->getLogger(),
                $options->getEventLogPolicy(),
            ),
        );
    }

    private function makeSwooleBackgroundTasks(): SwooleBackgroundTasks
    {
        $periodicTasks = [];
        $sweeper = $this->makeRetentionSweeper();
        if ($sweeper !== null) {
            $periodicTasks[] = new PeriodicTask(
                RetentionSweeper::TASK_NAME,
                RetentionSweeper::DEFAULT_INTERVAL_SECONDS,
                static function () use ($sweeper): void {
                    $sweeper->sweep();
                },
            );
        }

        $longLivedTasks = [];
        $daemon = $this->makeReplicaDaemon(hostManagedShutdown: true);
        if ($daemon !== null) {
            $longLivedTasks[] = new LongLivedTask(
                LdapReplica::TASK_NAME,
                $daemon->run(...),
                $daemon->stop(...),
            );
        }
        $forwardWorker = $this->makeForwardWorker(useCoroutineSleeper: true);
        if ($forwardWorker !== null) {
            $longLivedTasks[] = new LongLivedTask(
                PasswordPolicyForwardWorker::TASK_NAME,
                $forwardWorker->run(...),
                $forwardWorker->stop(...),
            );
        }

        return new SwooleBackgroundTasks(
            $periodicTasks,
            $longLivedTasks,
            $this->get(ServerOptions::class)->getLogger(),
        );
    }

    private function makePcntlBackgroundTasks(): PcntlBackgroundTasks
    {
        $options = $this->get(ServerOptions::class);

        $periodicTasks = [];
        if ($this->journalRetentionPolicyIfSweepable() !== null) {
            $periodicTasks[] = new PeriodicTask(
                RetentionSweeper::TASK_NAME,
                RetentionSweeper::DEFAULT_INTERVAL_SECONDS,
                function (): void {
                    $this->makeRetentionSweeper()?->sweep();
                },
            );
        }

        $longLivedTasks = [];
        if ($options->getReplicaConfig() !== null) {
            $longLivedTasks[] = new LongLivedTask(
                LdapReplica::TASK_NAME,
                function (): void {
                    $this->makeReplicaDaemon(hostManagedShutdown: false)?->run();
                },
            );
        }
        if ($this->makeForwardWorker(useCoroutineSleeper: false) !== null) {
            $longLivedTasks[] = new LongLivedTask(
                PasswordPolicyForwardWorker::TASK_NAME,
                function (): void {
                    $this->makeForwardWorker(useCoroutineSleeper: false)?->run();
                },
            );
        }

        return new PcntlBackgroundTasks(
            periodicTasks: $periodicTasks,
            longLivedTasks: $longLivedTasks,
            logger: $options->getLogger(),
        );
    }

    /**
     * The replica password-policy forward worker when replica mode + password policy are configured, else null.
     */
    private function makeForwardWorker(bool $useCoroutineSleeper): ?PasswordPolicyForwardWorker
    {
        $options = $this->get(ServerOptions::class);
        $config = $options->getReplicaConfig();

        if ($config === null || !$options->isPasswordPolicyEnabled()) {
            return null;
        }

        return new PasswordPolicyForwardWorker(
            $this->get(ReplicaPasswordStateStoreInterface::class),
            new LdapClientForwardStateSender(new PrimaryConnectionFactory($config)),
            $useCoroutineSleeper
                ? new CoroutineSleeper()
                : new BlockingSleeper(),
            signals: $useCoroutineSleeper
                ? null
                : new PcntlShutdownSignals(),
            logger: $options->getLogger(),
        );
    }

    /**
     * The replica sync daemon when replica mode is configured, else null.
     *
     * @param bool $hostManagedShutdown true under Swoole (the runner calls stop()), false under PCNTL (the forked child owns its signals)
     */
    private function makeReplicaDaemon(bool $hostManagedShutdown): ?LdapReplica
    {
        $options = $this->get(ServerOptions::class);
        $config = $options->getReplicaConfig();
        $storage = $options->getStorage();

        if ($config === null || $storage === null) {
            return null;
        }

        // Pair reconciliation with forwarding: the store drops forwarded state once the primary's entry replicates back.
        $passwordStateStore = $options->isPasswordPolicyEnabled()
            ? $this->get(ReplicaPasswordStateStoreInterface::class)
            : null;

        return $hostManagedShutdown
            ? LdapReplica::forSwoole(
                $config,
                $storage,
                $options->getLogger(),
                signals: null,
                passwordStateStore: $passwordStateStore,
            )
            : LdapReplica::forPcntl(
                $config,
                $storage,
                $options->getLogger(),
                passwordStateStore: $passwordStateStore,
            );
    }

    /**
     * The child-to-parent operation rollup for the forking runner, over the shared in-memory recorder; built only when
     * cn=monitor is enabled.
     */
    private function makeOperationRollup(): ?OperationRollupCoordinator
    {
        if (!$this->get(ServerOptions::class)->isMonitorEnabled()) {
            return null;
        }

        return $this->get(OperationRollupCoordinator::class);
    }

    /**
     * The PCNTL parent publishes connection metrics to a file for forked children (serving cn=monitor) to read; built
     * only when cn=monitor is enabled.
     */
    private function makeSnapshotPublisher(): ?SnapshotPublisher
    {
        $options = $this->get(ServerOptions::class);

        if (!$options->isMonitorEnabled()) {
            return null;
        }

        return new SnapshotPublisher(
            $this->get(InMemoryMetricsRecorder::class),
            new FileSnapshotWriter($this->monitorSnapshotPath($options)),
        );
    }

    /**
     * Builds a protocol factory from a (possibly reloaded) set of options via a fresh container.
     *
     * @return Closure(ServerOptions): ServerProtocolFactoryInterface
     */
    private function makeProtocolFactoryProvider(): Closure
    {
        $proxyOptions = $this->has(ProxyOptions::class)
            ? $this->get(ProxyOptions::class)
            : null;
        // Carry the backend across reloads so a SIGHUP does not drop the configured storage.
        $backend = $this->backendOrNull();

        // Share the metrics state across reloads so SIGHUP does not reset the counters or detach cn=monitor. The rollup
        // coordinator is shared so a reloaded middleware streams to the same channel the (persistent) runner bound.
        $metricsRecorder = $this->get(MetricsRecorderInterface::class);
        $metricsSnapshots = $this->get(MetricsSnapshotProvider::class);
        $inMemoryMetrics = $this->get(InMemoryMetricsRecorder::class);
        $operationRollup = $this->makeOperationRollup();

        return static function (ServerOptions $options) use (
            $proxyOptions,
            $backend,
            $metricsRecorder,
            $metricsSnapshots,
            $inMemoryMetrics,
            $operationRollup,
        ): ServerProtocolFactoryInterface {
            $instances = [
                ServerOptions::class => $options,
                MetricsRecorderInterface::class => $metricsRecorder,
                MetricsSnapshotProvider::class => $metricsSnapshots,
                InMemoryMetricsRecorder::class => $inMemoryMetrics,
            ];

            if ($backend !== null) {
                $instances[WritableStorageBackend::class] = $backend;
            }

            if ($proxyOptions !== null) {
                $instances[ProxyOptions::class] = $proxyOptions;
            }

            if ($operationRollup !== null) {
                $instances[OperationRollupCoordinator::class] = $operationRollup;
            }

            return (new Container($instances))->get(ServerProtocolFactoryInterface::class);
        };
    }

    private function makeSocketServerFactory(): SocketServerFactory
    {
        $serverOptions = $this->get(ServerOptions::class);

        return new SocketServerFactory(
            options: $serverOptions,
            logger: $serverOptions->getLogger(),
        );
    }

    private function makeServerAuthorizer(): ServerAuthorization
    {
        return new ServerAuthorization($this->get(ServerOptions::class));
    }
}
