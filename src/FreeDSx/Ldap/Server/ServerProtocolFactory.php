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
use FreeDSx\Ldap\Protocol\Bind\AnonymousBind;
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
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
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
use FreeDSx\Ldap\Server\Middleware\CriticalControlMiddleware;
use FreeDSx\Ldap\Server\Middleware\OperationAuditMiddleware;
use FreeDSx\Ldap\Server\Middleware\OperationAuthorizationMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\HandlerInvoker;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareChain;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyBindGuard;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordResetGate;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Socket;

class ServerProtocolFactory
{
    public function __construct(
        private readonly HandlerFactoryInterface $handlerFactory,
        private readonly ServerOptions $options,
        private readonly ServerAuthorization $serverAuthorization,
        private readonly PasswordPolicyEngine $passwordPolicyEngine,
        private readonly ServerProtocolHandlerFactory $routeResolver,
        private readonly PasswordModifyTargetResolver $targetResolver,
        private readonly PasswordHashService $hashService,
        private readonly WriteOperationDispatcher $writeDispatcher,
        private readonly PasswordPolicyComponentFactory $policyComponentFactory,
    ) {}

    public function make(
        Socket $socket,
        ConnectionContext $context = new ConnectionContext(),
    ): ServerProtocolHandler {
        $serverQueue = new ServerQueue(
            $socket,
            maxReceiveSize: $this->options->getMaxRequestSize(),
        );
        $eventLogger = new EventLogger(
            $this->options->getLogger(),
            $this->options->getEventLogPolicy(),
            $context->toLogContext(),
        );

        $backend = $this->handlerFactory->makeBackend();
        $passwordAuthenticator = $this->handlerFactory->makePasswordAuthenticator();

        $policyContext = null;
        if ($this->options->isPasswordPolicyEnabled()) {
            $policyContext = new PasswordPolicyContext();
            $passwordAuthenticator = $this->decoratePasswordAuthenticator(
                $passwordAuthenticator,
                $backend,
                $policyContext,
                $eventLogger,
            );
        }

        $authenticators = [
            new SimpleBind(
                queue: $serverQueue,
                authenticator: $passwordAuthenticator,
                eventLogger: $eventLogger,
                passwordPolicyContext: $policyContext,
            ),
            new AnonymousBind(
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

        $dispatchAuthorizer = new DispatchAuthorizer(
            $this->serverAuthorization,
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
                    new CriticalControlMiddleware($this->routeResolver),
                    new OperationAuthorizationMiddleware(
                        $this->routeResolver,
                        $this->options->getAccessControl(),
                        $eventLogger,
                    ),
                    new OperationAuditMiddleware(new OperationAuditor($eventLogger)),
                ],
                new HandlerInvoker($handlerProvider),
            ),
            authorizer: $this->serverAuthorization,
            authenticator: new Authenticator($authenticators),
            dispatchAuthorizer: $dispatchAuthorizer,
            eventLogger: $eventLogger,
            passwordPolicyContext: $policyContext,
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
