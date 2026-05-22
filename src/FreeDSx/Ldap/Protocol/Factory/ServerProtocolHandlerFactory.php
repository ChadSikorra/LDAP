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

namespace FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerProtocolHandlerInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHasher;
use FreeDSx\Ldap\Server\Backend\Write\PasswordPolicyWriteHandler;
use FreeDSx\Ldap\Server\Backend\Write\SystemChangeWriter;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyChangeGuard;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\RequestHistory;
use FreeDSx\Ldap\ServerOptions;

/**
 * Determines the correct handler for the request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerProtocolHandlerFactory
{
    public function __construct(
        private readonly HandlerFactoryInterface $handlerFactory,
        private readonly ServerOptions $options,
        private readonly RequestHistory $requestHistory,
        private readonly ServerQueue $queue,
        private readonly EventLogger $eventLogger = new EventLogger(null),
        private readonly ?PasswordPolicyEngine $passwordPolicyEngine = null,
        private readonly ?PasswordPolicyContext $passwordPolicyContext = null,
    ) {}

    public function get(
        RequestInterface $request,
        ControlBag $controls,
    ): ServerProtocolHandlerInterface {
        if ($request instanceof AbandonRequest) {
            return new ServerProtocolHandler\ServerAbandonHandler();
        } elseif ($request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_CANCEL) {
            return new ServerProtocolHandler\ServerCancelHandler($this->queue);
        } elseif ($request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_WHOAMI) {
            return new ServerProtocolHandler\ServerWhoAmIHandler($this->queue);
        } elseif ($request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_PWD_MODIFY) {
            return new ServerProtocolHandler\ServerPasswordModifyHandler(
                queue: $this->queue,
                backend: $this->handlerFactory->makeBackend(),
                writeDispatcher: $this->handlerFactory->makeWriteDispatcher(),
                accessControl: $this->options->getAccessControl(),
                identityResolver: $this->handlerFactory->makeIdentityResolverChain(),
                eventLogger: $this->eventLogger,
                hasher: new PasswordHasher($this->options->getPasswordHashScheme()),
                changeGuard: $this->makePasswordPolicyChangeGuard(),
                passwordPolicyContext: $this->passwordPolicyContext,
            );
        } elseif ($request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_START_TLS) {
            return new ServerProtocolHandler\ServerStartTlsHandler(
                options: $this->options,
                queue: $this->queue,
                eventLogger: $this->eventLogger,
            );
        } elseif ($request instanceof ExtendedRequest) {
            return new ServerProtocolHandler\ServerUnsupportedExtendedHandler($this->queue);
        } elseif ($this->isRootDseSearch($request)) {
            return $this->getRootDseHandler();
        } elseif ($this->isSubschemaSearch($request)) {
            return new ServerProtocolHandler\ServerSubschemaHandler(
                options: $this->options,
                queue: $this->queue,
            );
        } elseif ($this->isPagingSearch($request, $controls)) {
            return $this->getPagingHandler();
        } elseif ($request instanceof SearchRequest) {
            return new ServerProtocolHandler\ServerSearchHandler(
                queue: $this->queue,
                backend: $this->handlerFactory->makeBackend(),
                filterEvaluator: $this->handlerFactory->makeFilterEvaluator(),
                accessControl: $this->options->getAccessControl(),
                schema: $this->options->getSchema(),
                limits: $this->options->makeSearchLimits(),
                eventLogger: $this->eventLogger,
            );
        } elseif ($request instanceof UnbindRequest) {
            return new ServerProtocolHandler\ServerUnbindHandler($this->queue);
        } else {
            $policyWriteHandler = $this->makePasswordPolicyWriteHandler();

            return new ServerProtocolHandler\ServerDispatchHandler(
                queue: $this->queue,
                backend: $this->handlerFactory->makeBackend(),
                writeDispatcher: $policyWriteHandler !== null
                    ? $this->handlerFactory->makeWriteDispatcher($policyWriteHandler)
                    : $this->handlerFactory->makeWriteDispatcher(),
                accessControl: $this->options->getAccessControl(),
                eventRecorder: new ServerProtocolHandler\DispatchEventRecorder($this->eventLogger),
                passwordPolicyContext: $this->passwordPolicyContext,
            );
        }
    }

    private function makePasswordPolicyWriteHandler(): ?PasswordPolicyWriteHandler
    {
        $guard = $this->makePasswordPolicyChangeGuard();
        if ($guard === null) {
            return null;
        }

        $backend = $this->handlerFactory->makeBackend();
        if (!$backend instanceof WriteHandlerInterface) {
            throw new RuntimeException(
                'A backend implementing WriteHandlerInterface is required to enforce policy on userPassword modifications.',
            );
        }

        return new PasswordPolicyWriteHandler(
            $backend,
            $guard,
            new SystemChangeWriter($this->handlerFactory->makeWriteDispatcher()),
        );
    }

    private function makePasswordPolicyChangeGuard(): ?PasswordPolicyChangeGuard
    {
        if (!$this->isPasswordPolicyActive()) {
            return null;
        }

        return new PasswordPolicyChangeGuard(
            $this->passwordPolicyEngine,
            new PasswordPolicyResolver(
                $this->handlerFactory->makeBackend(),
                $this->options->getDefaultPasswordPolicyDn(),
                $this->options->getPasswordPolicy(),
            ),
            $this->passwordPolicyContext,
            $this->eventLogger,
        );
    }

    /**
     * @phpstan-assert-if-true !null $this->passwordPolicyEngine
     * @phpstan-assert-if-true !null $this->passwordPolicyContext
     */
    private function isPasswordPolicyActive(): bool
    {
        return $this->passwordPolicyEngine !== null
            && $this->passwordPolicyContext !== null
            && $this->options->isPasswordPolicyEnabled();
    }

    private function isSubschemaSearch(RequestInterface $request): bool
    {
        if (!$request instanceof SearchRequest) {
            return false;
        }
        $subschemaEntry = $this->options->getSubschemaEntry()->toString();

        return $request->getScope() === SearchRequest::SCOPE_BASE_OBJECT
            && strtolower((string) $request->getBaseDn()) === strtolower($subschemaEntry);
    }

    private function isRootDseSearch(RequestInterface $request): bool
    {
        if (!$request instanceof SearchRequest) {
            return false;
        }

        return $request->getScope() === SearchRequest::SCOPE_BASE_OBJECT
                && ((string) $request->getBaseDn() === '');
    }

    private function isPagingSearch(
        RequestInterface $request,
        ControlBag $controls,
    ): bool {
        return $request instanceof SearchRequest
            && $controls->has(Control::OID_PAGING);
    }

    private function getRootDseHandler(): ServerProtocolHandler\ServerRootDseHandler
    {
        $rootDseHandler = $this->handlerFactory->makeRootDseHandler();

        return new ServerProtocolHandler\ServerRootDseHandler(
            options: $this->options,
            queue: $this->queue,
            rootDseHandler: $rootDseHandler,
        );
    }

    private function getPagingHandler(): ServerProtocolHandlerInterface
    {
        return new ServerProtocolHandler\ServerPagingHandler(
            queue: $this->queue,
            backend: $this->handlerFactory->makeBackend(),
            filterEvaluator: $this->handlerFactory->makeFilterEvaluator(),
            accessControl: $this->options->getAccessControl(),
            requestHistory: $this->requestHistory,
            schema: $this->options->getSchema(),
            limits: $this->options->makeSearchLimits(),
            eventLogger: $this->eventLogger,
        );
    }
}
