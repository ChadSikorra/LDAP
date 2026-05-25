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
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\Write\PasswordPolicyWriteHandler;
use FreeDSx\Ldap\Server\Backend\Write\SystemChangeWriter;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyService;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyTargetResolver;
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
readonly class ServerProtocolHandlerFactory implements HandlerRouteResolverInterface
{
    public function __construct(
        private HandlerFactoryInterface $handlerFactory,
        private ServerOptions $options,
        private RequestHistory $requestHistory,
        private ServerQueue $queue,
        private EventLogger $eventLogger = new EventLogger(null),
        private ?PasswordPolicyEngine $passwordPolicyEngine = null,
        private ?PasswordPolicyContext $passwordPolicyContext = null,
    ) {}

    public function get(
        RequestInterface $request,
        ControlBag $controls,
    ): ServerProtocolHandlerInterface {
        return match ($this->routeIdFor($request, $controls)) {
            HandlerId::Abandon => new ServerProtocolHandler\ServerAbandonHandler(),
            HandlerId::Cancel => new ServerProtocolHandler\ServerCancelHandler($this->queue),
            HandlerId::WhoAmI => new ServerProtocolHandler\ServerWhoAmIHandler($this->queue),
            HandlerId::PasswordModify => $this->getPasswordModifyHandler(),
            HandlerId::StartTls => $this->getStartTlsHandler(),
            HandlerId::UnsupportedExtended => new ServerProtocolHandler\ServerUnsupportedExtendedHandler($this->queue),
            HandlerId::RootDse => $this->getRootDseHandler(),
            HandlerId::Subschema => $this->getSubschemaHandler(),
            HandlerId::Paging => $this->getPagingHandler(),
            HandlerId::Search => $this->getSearchHandler(),
            HandlerId::Unbind => new ServerProtocolHandler\ServerUnbindHandler($this->queue),
            HandlerId::Dispatch => $this->getDispatchHandler(),
        };
    }

    public function routeIdFor(
        RequestInterface $request,
        ControlBag $controls,
    ): HandlerId {
        return match (true) {
            $request instanceof AbandonRequest => HandlerId::Abandon,
            $request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_CANCEL => HandlerId::Cancel,
            $request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_WHOAMI => HandlerId::WhoAmI,
            $request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_PWD_MODIFY => HandlerId::PasswordModify,
            $request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_START_TLS => HandlerId::StartTls,
            $request instanceof ExtendedRequest => HandlerId::UnsupportedExtended,
            $this->isRootDseSearch($request) => HandlerId::RootDse,
            $this->isSubschemaSearch($request) => HandlerId::Subschema,
            $this->isPagingSearch($request, $controls) => HandlerId::Paging,
            $request instanceof SearchRequest => HandlerId::Search,
            $request instanceof UnbindRequest => HandlerId::Unbind,
            default => HandlerId::Dispatch,
        };
    }

    private function getPasswordModifyHandler(): ServerProtocolHandler\ServerPasswordModifyHandler
    {
        return new ServerProtocolHandler\ServerPasswordModifyHandler(
            queue: $this->queue,
            service: new PasswordModifyService(
                targetResolver: new PasswordModifyTargetResolver(
                    $this->handlerFactory->makeBackend(),
                    $this->handlerFactory->makeIdentityResolverChain(),
                ),
                accessControl: $this->options->getAccessControl(),
                writeDispatcher: $this->handlerFactory->makeWriteDispatcher(),
                hashService: new PasswordHashService($this->options->getPasswordHashScheme()),
                changeGuard: $this->makePasswordPolicyChangeGuard(),
                passwordPolicyContext: $this->passwordPolicyContext,
            ),
            eventLogger: $this->eventLogger,
            passwordPolicyContext: $this->passwordPolicyContext,
        );
    }

    private function getStartTlsHandler(): ServerProtocolHandler\ServerStartTlsHandler
    {
        return new ServerProtocolHandler\ServerStartTlsHandler(
            options: $this->options,
            queue: $this->queue,
            eventLogger: $this->eventLogger,
        );
    }

    private function getSubschemaHandler(): ServerProtocolHandler\ServerSubschemaHandler
    {
        return new ServerProtocolHandler\ServerSubschemaHandler(
            options: $this->options,
            queue: $this->queue,
        );
    }

    private function getSearchHandler(): ServerProtocolHandler\ServerSearchHandler
    {
        return new ServerProtocolHandler\ServerSearchHandler(
            queue: $this->queue,
            backend: $this->handlerFactory->makeBackend(),
            filterEvaluator: $this->handlerFactory->makeFilterEvaluator(),
            accessControl: $this->options->getAccessControl(),
            schema: $this->options->getSchema(),
            limits: $this->options->makeSearchLimits(),
            eventLogger: $this->eventLogger,
        );
    }

    private function getDispatchHandler(): ServerProtocolHandler\ServerDispatchHandler
    {
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
