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
use FreeDSx\Ldap\Protocol\Authorization\DispatchAuthorizer;
use FreeDSx\Ldap\Protocol\Authorization\ProxiedAuthorizationResolver;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\MechanismOptionsBuilderFactory;
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
use FreeDSx\Ldap\Server\Backend\Auth\PasswordPolicyAwareAuthenticator;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\SaslBindPolicyEnforcer;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\SystemChangeWriter;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\OperationAuditor;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\AssertionEvaluator;
use FreeDSx\Ldap\Server\Middleware\AssertionMiddleware;
use FreeDSx\Ldap\Server\Middleware\AuthorizationResolutionMiddleware;
use FreeDSx\Ldap\Server\Middleware\BindMiddleware;
use FreeDSx\Ldap\Server\Middleware\CriticalControlMiddleware;
use FreeDSx\Ldap\Server\Middleware\OperationAuditMiddleware;
use FreeDSx\Ldap\Server\Middleware\OperationAuthorizationMiddleware;
use FreeDSx\Ldap\Server\Middleware\OperationErrorMiddleware;
use FreeDSx\Ldap\Server\Middleware\RequestValidationMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\HandlerInvoker;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareChain;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyBindGuard;
use FreeDSx\Ldap\Protocol\Queue\Response\PasswordPolicyResponseInterceptor;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordResetGate;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Socket;

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
    ) {}

    protected function serverOptions(): ServerOptions
    {
        return $this->options;
    }

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

        $serverQueue = $this->makeServerQueue(
            $socket,
            $interceptors,
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
        $saslMechanisms = $this->options->getSaslMechanisms();

        if (!empty($saslMechanisms)) {
            $responseFactory = new ResponseFactory();
            $authenticators[] = new SaslBind(
                queue: $serverQueue,
                exchange: new SaslExchange(
                    $serverQueue,
                    $responseFactory,
                    new MechanismOptionsBuilderFactory($passwordAuthenticator),
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
            new ProxiedAuthorizationResolver(
                $this->options->getAccessControl(),
                $backend,
                $this->handlerFactory->makeIdentityResolverChain(),
                $eventLogger,
            ),
        );

        $handlerProvider = new ProtocolHandlerProvider(
            routeResolver: $this->routeResolver,
            handlerFactory: $this->handlerFactory,
            options: $this->options,
            targetResolver: $this->targetResolver,
            hashService: $this->hashService,
            writeDispatcher: $this->writeDispatcher,
            policyComponentFactory: $this->policyComponentFactory,
            queue: $serverQueue,
            eventLogger: $eventLogger,
            requestHistory: new RequestHistory(),
            passwordPolicyContext: $policyContext,
        );

        return new ServerProtocolHandler(
            queue: $serverQueue,
            requestPipeline: new MiddlewareChain(
                [
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
                    new OperationErrorMiddleware(
                        $serverQueue,
                        $backend,
                        $this->options->getAccessControl(),
                    ),
                    new OperationAuditMiddleware(new OperationAuditor($eventLogger)),
                    new CriticalControlMiddleware($this->routeResolver),
                    new OperationAuthorizationMiddleware(
                        $this->routeResolver,
                        $this->options->getAccessControl(),
                        $this->options->getPrivilegedControls(),
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

    private function makeBindGuard(
        PasswordPolicyContext $policyContext,
        EventLogger $eventLogger,
    ): PasswordPolicyBindGuard {
        return new PasswordPolicyBindGuard(
            $this->passwordPolicyEngine,
            new SystemChangeWriter($this->handlerFactory->makeWriteDispatcher()),
            $policyContext,
            $eventLogger,
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
