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
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\AllowUserChangeConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\HistoryConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\MinAgeConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\QualityConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\SafeModifyConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyComponentFactory;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
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
     * @var array<class-string, callable>
     */
    private array $instanceFactory = [];

    /**
     * These are classes that should never cache an instance when retrieved from the container.
     */
    private const FACTORY_ONLY = [
        HandlerFactoryInterface::class,
        ServerAuthorization::class,
    ];

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
        );
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
        return new HandlerFactory($this->get(ServerOptions::class));
    }

    private function makeServerRunner(): ServerRunnerInterface
    {
        $options = $this->get(ServerOptions::class);
        $protocolFactoryProvider = $this->makeProtocolFactoryProvider();

        if ($options->getUseSwooleRunner()) {
            return new SwooleServerRunner(
                serverProtocolFactory: $protocolFactoryProvider($options),
                options: $options,
                socketServerFactory: $this->get(SocketServerFactory::class),
                protocolFactoryProvider: $protocolFactoryProvider,
            );
        }

        return new PcntlServerRunner(
            serverProtocolFactory: $protocolFactoryProvider($options),
            options: $options,
            socketServerFactory: $this->get(SocketServerFactory::class),
            protocolFactoryProvider: $protocolFactoryProvider,
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

        return static function (ServerOptions $options) use ($proxyOptions): ServerProtocolFactoryInterface {
            $instances = [ServerOptions::class => $options];

            if ($proxyOptions !== null) {
                $instances[ProxyOptions::class] = $proxyOptions;
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
