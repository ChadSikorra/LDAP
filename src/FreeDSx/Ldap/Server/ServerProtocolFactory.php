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

namespace FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Protocol\Authenticator;
use FreeDSx\Ldap\Protocol\Authorization\AuthzIdResolver;
use FreeDSx\Ldap\Protocol\Authorization\DispatchAuthorizer;
use FreeDSx\Ldap\Protocol\Authorization\ProxiedAuthorizationResolver;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\ExternalMechanismOptionsBuilder;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\MechanismOptionsBuilderFactory;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\MechanismOptionsBuilderInterface;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\Bind\Sasl\SaslExchange;
use FreeDSx\Ldap\Protocol\Bind\SaslBind;
use FreeDSx\Ldap\Protocol\Bind\SimpleBind;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\SaslOptions;
use FreeDSx\Sasl\Sasl;
use FreeDSx\Ldap\Protocol\Factory\ProtocolHandlerProvider;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyTargetResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyComponentFactory;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\Backend\Auth\ManagerAwareAuthenticator;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordPolicyAwareAuthenticator;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Sasl\External\SubjectDnCredentialMapper;
use FreeDSx\Ldap\Server\Backend\Auth\SaslBindPolicyEnforcer;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\SystemChange\LocalStateSystemChangeWriter;
use FreeDSx\Ldap\Server\Backend\Write\SystemChange\SystemChangeWriter;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\OperationAuditor;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\AssertionEvaluator;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\MetricsSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Rollup\OperationRollupCoordinator;
use FreeDSx\Ldap\Server\Middleware\AssertionMiddleware;
use FreeDSx\Ldap\Server\Middleware\AuthorizationResolutionMiddleware;
use FreeDSx\Ldap\Server\Middleware\MetricsMiddleware;
use FreeDSx\Ldap\Server\Middleware\BindMiddleware;
use FreeDSx\Ldap\Server\Middleware\CriticalControlMiddleware;
use FreeDSx\Ldap\Server\Middleware\OperationAuditMiddleware;
use FreeDSx\Ldap\Server\Middleware\OperationAuthorizationMiddleware;
use FreeDSx\Ldap\Server\Middleware\OperationErrorMiddleware;
use FreeDSx\Ldap\Server\Middleware\ReadOnlyMiddleware;
use FreeDSx\Ldap\Server\Middleware\RequestValidationMiddleware;
use FreeDSx\Ldap\Server\Middleware\ResourceLimitMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\HandlerInvoker;
use FreeDSx\Ldap\Server\SearchLimit\SearchLimitResolver;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareChain;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\CoroutineSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\BindStrategy\EntryBindStrategy;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\BindStrategy\ReplicaBindStrategy;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyBindGuard;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Protocol\Queue\Response\MetricsResponseInterceptor;
use FreeDSx\Ldap\Protocol\Queue\Response\PasswordPolicyResponseInterceptor;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordResetGate;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Socket;

use function in_array;

class ServerProtocolFactory implements ServerProtocolFactoryInterface
{
    use ServerConnectionScaffoldingTrait;

    public function __construct(
        private readonly HandlerFactoryInterface $handlerFactory,
        private readonly ServerOptions $options,
        private readonly PasswordPolicyEngine $passwordPolicyEngine,
        private readonly ServerProtocolHandlerFactory $routeResolver,
        private readonly PasswordModifyTargetResolver $targetResolver,
        private readonly PasswordHashService $hashService,
        private readonly WriteOperationDispatcher $writeDispatcher,
        private readonly PasswordPolicyComponentFactory $policyComponentFactory,
        private readonly MetricsRecorderInterface $metricsRecorder = new NullMetricsRecorder(),
        private readonly MetricsSnapshotProvider $metricsSnapshots = new InMemoryMetricsRecorder(),
        private readonly ?OperationRollupCoordinator $operationRollup = null,
        private readonly ?ReplicaPasswordStateStoreInterface $replicaPasswordStateStore = null,
    ) {}

    public function make(
        Socket $socket,
        ConnectionContext $context = new ConnectionContext(),
    ): ServerProtocolHandler {
        $eventLogger = $this->makeEventLogger($context);

        $backend = $this->handlerFactory->makeBackend();
        $passwordAuthenticator = $this->handlerFactory->makePasswordAuthenticator();

        $policyContext = null;
        $interceptors = [];
        if ($this->options->isPasswordPolicyEnabled()) {
            $policyContext = new PasswordPolicyContext();
            $interceptors[] = new PasswordPolicyResponseInterceptor($policyContext);
            $passwordAuthenticator = $this->decoratePasswordAuthenticator(
                $passwordAuthenticator,
                $backend,
                $policyContext,
                $eventLogger,
            );
        }

        $manager = $this->options->getManager();
        if ($manager !== null) {
            // Outermost: the manager is recognized before the backend and password policy, so it is lockout-exempt.
            $passwordAuthenticator = new ManagerAwareAuthenticator(
                $passwordAuthenticator,
                $manager,
                $this->hashService,
            );
        }

        if (!$this->metricsRecorder instanceof NullMetricsRecorder) {
            $interceptors[] = new MetricsResponseInterceptor($this->metricsRecorder);
        }

        $serverQueue = $this->makeServerQueue(
            $socket,
            $interceptors,
            $this->metricsRecorder,
        );

        $authenticators = [
            new SimpleBind(
                queue: $serverQueue,
                authenticator: $passwordAuthenticator,
                eventLogger: $eventLogger,
            ),
            $this->makeAnonymousBind(
                $serverQueue,
                $eventLogger,
            ),
        ];

        $authzIdResolver = new AuthzIdResolver(
            $this->options->getAccessControl(),
            $backend,
            $this->handlerFactory->makeIdentityResolverChain(),
            $eventLogger,
        );

        $saslMechanisms = $this->options->getSaslMechanisms();

        if (!empty($saslMechanisms)) {
            $responseFactory = new ResponseFactory();
            $authenticators[] = new SaslBind(
                queue: $serverQueue,
                exchange: new SaslExchange(
                    $serverQueue,
                    $responseFactory,
                    $this->makeOptionsBuilderFactory(
                        $passwordAuthenticator,
                        $serverQueue,
                        $saslMechanisms,
                        $authzIdResolver,
                    ),
                    $authzIdResolver,
                ),
                sasl: new Sasl(new SaslOptions(
                    supported: $this->parseKnownMechanisms($saslMechanisms),
                )),
                mechanisms: $saslMechanisms,
                responseFactory: $responseFactory,
                eventLogger: $eventLogger,
                policyEnforcer: $policyContext !== null
                    ? $this->makeSaslPolicyEnforcer($backend, $policyContext, $eventLogger)
                    : null,
            );
        }

        // Per connection: the bound-token state must not be shared across connections (e.g., coroutines).
        $authorization = new ServerAuthorization($this->options);

        $dispatchAuthorizer = new DispatchAuthorizer(
            $authorization,
            new PasswordResetGate(),
            new ProxiedAuthorizationResolver($authzIdResolver),
        );

        $searchLimitResolver = new SearchLimitResolver(
            $this->options->getSearchLimitRules(),
            $this->options->makeSearchLimits(),
        );
        $searchLimitResolver->setBackend($backend);

        $handlerProvider = new ProtocolHandlerProvider(
            routeResolver: $this->routeResolver,
            handlerFactory: $this->handlerFactory,
            options: $this->options,
            targetResolver: $this->targetResolver,
            hashService: $this->hashService,
            writeDispatcher: $this->writeDispatcher,
            policyComponentFactory: $this->policyComponentFactory,
            passwordPolicyEngine: $this->passwordPolicyEngine,
            queue: $serverQueue,
            eventLogger: $eventLogger,
            requestHistory: new RequestHistory(),
            passwordPolicyContext: $policyContext,
            metricsSnapshots: $this->metricsSnapshots,
        );

        $replicaConfig = $this->options->getReplicaConfig();

        return new ServerProtocolHandler(
            queue: $serverQueue,
            requestPipeline: new MiddlewareChain(
                [
                    // First, so it times and records every message (including binds) regardless of outcome.
                    new MetricsMiddleware(
                        $this->metricsRecorder,
                        $this->operationRollup,
                    ),
                    // Order matters: AuthorizationResolutionMiddleware injects the token via withToken(), so
                    // every middleware after it may rely on tokenOrFail(). Keep token consumers below it.
                    new RequestValidationMiddleware(),
                    new BindMiddleware(
                        $authorization,
                        new Authenticator($authenticators),
                    ),
                    new AuthorizationResolutionMiddleware(
                        $dispatchAuthorizer,
                        $policyContext,
                    ),
                    // The token is resolved at this point, so per-identity limits can be attached.
                    new ResourceLimitMiddleware($searchLimitResolver),
                    new OperationErrorMiddleware(
                        $serverQueue,
                        $backend,
                        $this->options->getAccessControl(),
                    ),
                    new OperationAuditMiddleware(new OperationAuditor($eventLogger)),
                    // Only present on a read-only replica; sits below OperationErrorMiddleware so a rejection renders,
                    // and before the ACL loop so a write short-circuits early.
                    ...($replicaConfig !== null
                        ? [new ReadOnlyMiddleware(
                            $serverQueue,
                            $replicaConfig,
                        )]
                        : []),
                    new CriticalControlMiddleware($this->routeResolver),
                    new OperationAuthorizationMiddleware(
                        $this->routeResolver,
                        $this->options->getAccessControl(),
                        $this->options->getPrivilegedControls(),
                        $this->options->getPrivilegedExtendedOps(),
                    ),
                    new AssertionMiddleware(new AssertionEvaluator(
                        $this->options->getFilterEvaluator(),
                        $backend,
                    )),
                ],
                new HandlerInvoker($handlerProvider),
            ),
            eventLogger: $eventLogger,
            connectionContext: $context,
        );
    }

    protected function serverOptions(): ServerOptions
    {
        return $this->options;
    }

    private function decoratePasswordAuthenticator(
        PasswordAuthenticatableInterface $inner,
        LdapBackendInterface $backend,
        PasswordPolicyContext $policyContext,
        EventLogger $eventLogger,
    ): PasswordPolicyAwareAuthenticator {
        return new PasswordPolicyAwareAuthenticator(
            $inner,
            $this->handlerFactory->makeIdentityResolverChain(),
            $backend,
            $this->makePasswordPolicyResolver($backend),
            $this->makeBindGuard($policyContext, $eventLogger),
        );
    }

    private function makeSaslPolicyEnforcer(
        LdapBackendInterface $backend,
        PasswordPolicyContext $policyContext,
        EventLogger $eventLogger,
    ): SaslBindPolicyEnforcer {
        return new SaslBindPolicyEnforcer(
            $this->handlerFactory->makeIdentityResolverChain(),
            $backend,
            $this->makePasswordPolicyResolver($backend),
            $this->makeBindGuard($policyContext, $eventLogger),
            $policyContext,
        );
    }

    private function makePasswordPolicyResolver(LdapBackendInterface $backend): PasswordPolicyResolver
    {
        return new PasswordPolicyResolver(
            $backend,
            $this->options->getDefaultPasswordPolicyDn(),
            $this->options->getPasswordPolicy(),
        );
    }

    /**
     * Builds the bind guard: replica-local worst-outcome state on a read-only replica, authoritative entry state otherwise.
     */
    private function makeBindGuard(
        PasswordPolicyContext $policyContext,
        EventLogger $eventLogger,
    ): PasswordPolicyBindGuard {
        $store = $this->replicaPasswordStateStore;

        $strategy = $store !== null
            ? new ReplicaBindStrategy($this->passwordPolicyEngine, $store)
            : new EntryBindStrategy($this->passwordPolicyEngine);
        $writer = $store !== null
            ? new LocalStateSystemChangeWriter($store)
            : new SystemChangeWriter($this->handlerFactory->makeWriteDispatcher());

        return new PasswordPolicyBindGuard(
            $this->passwordPolicyEngine,
            $strategy,
            $writer,
            $policyContext,
            $eventLogger,
            $this->makeSleeper(),
        );
    }

    private function makeSleeper(): SleeperInterface
    {
        return $this->options->getUseSwooleRunner()
            ? new CoroutineSleeper()
            : new BlockingSleeper();
    }

    /**
     * @param string[] $saslMechanisms
     */
    private function makeOptionsBuilderFactory(
        PasswordAuthenticatableInterface $authenticator,
        ServerQueue $queue,
        array $saslMechanisms,
        AuthzIdResolver $authzIdResolver,
    ): MechanismOptionsBuilderFactory {
        if (!in_array(ServerOptions::SASL_EXTERNAL, $saslMechanisms, true)) {
            return new MechanismOptionsBuilderFactory($authenticator);
        }

        return new MechanismOptionsBuilderFactory(
            $authenticator,
            fn(): MechanismOptionsBuilderInterface => new ExternalMechanismOptionsBuilder(
                $queue,
                $this->options,
                $this->options->getExternalCredentialMapper() ?? new SubjectDnCredentialMapper(),
                $authzIdResolver,
            ),
        );
    }

    /**
     * Converts mechanism name strings into known MechanismName values, discarding unrecognised ones.
     *
     * @param string[] $mechanisms
     * @return MechanismName[]
     */
    private function parseKnownMechanisms(array $mechanisms): array
    {
        $known = [];
        foreach ($mechanisms as $name) {
            $mech = MechanismName::tryFrom($name);
            if ($mech !== null) {
                $known[] = $mech;
            }
        }

        return $known;
    }
}
