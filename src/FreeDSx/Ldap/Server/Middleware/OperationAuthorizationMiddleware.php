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

namespace FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Protocol\Factory\HandlerId;
use FreeDSx\Ldap\Protocol\Factory\HandlerRouteResolverInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\OperationType;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\OperationAuditor;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Authorizes the operation before dispatch and audits denials.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class OperationAuthorizationMiddleware implements MiddlewareInterface
{
    /**
     * Controls that require an explicit ControlRule grant before they may be used on a write.
     */
    private const PRIVILEGED_CONTROLS = [Control::OID_RELAX_RULES];

    private OperationAuditor $auditor;

    public function __construct(
        private HandlerRouteResolverInterface $routeResolver,
        private AccessControlInterface $accessControl,
        EventLogger $eventLogger = new EventLogger(null),
    ) {
        $this->auditor = new OperationAuditor($eventLogger);
    }

    /**
     * @throws OperationException
     */
    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): OperationResult {
        $routeId = $this->routeResolver->routeIdFor(
            $context->message->getRequest(),
            $context->message->controls(),
        );

        if ($routeId === HandlerId::Search || $routeId === HandlerId::Paging) {
            $this->authorizeSearch(
                $context->message,
                $context->token,
            );
        } elseif ($routeId === HandlerId::Dispatch) {
            $this->authorizeDispatch(
                $context->message,
                $context->token,
            );
        }

        return $next->handle($context);
    }

    /**
     * @throws OperationException
     */
    private function authorizeSearch(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): void {
        $request = $message->getRequest();

        if (!$request instanceof SearchRequest) {
            return;
        }

        $baseDn = $request->getBaseDn();

        if ($baseDn === null) {
            return;
        }

        try {
            $this->accessControl->authorizeOperation(
                OperationType::Search,
                $token,
                $baseDn,
            );
        } catch (OperationException $e) {
            $this->auditor->recordSearchFailure(
                $message,
                $e,
                $token,
            );

            throw $e;
        }
    }

    /**
     * @throws OperationException
     */
    private function authorizeDispatch(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): void {
        $request = $message->getRequest();

        try {
            $this->authorizeRequest(
                $request,
                $token,
            );
            $this->authorizeWriteAttributes(
                $request,
                $token,
            );

            if ($request instanceof CompareRequest) {
                $this->accessControl->authorizeAttribute(
                    $token,
                    $request->getDn(),
                    $request->getFilter()->getAttribute(),
                );

                return;
            }

            $this->authorizeControls(
                $request,
                $message->controls(),
                $token,
            );
        } catch (OperationException $e) {
            $this->auditor->recordFailure(
                $message,
                $e,
                $token,
            );

            throw $e;
        }
    }

    /**
     * @throws OperationException
     */
    private function authorizeRequest(
        RequestInterface $request,
        TokenInterface $token,
    ): void {
        if ($request instanceof ModifyDnRequest) {
            $this->authorizeModifyDn(
                $request,
                $token,
            );

            return;
        }

        $operationType = OperationType::fromRequest($request);

        if ($operationType === null || $operationType === OperationType::Search) {
            return;
        }

        $dn = $this->dnFor($request);

        if ($dn === null) {
            return;
        }

        $this->accessControl->authorizeOperation(
            $operationType,
            $token,
            $dn,
        );
    }

    /**
     * @throws OperationException
     */
    private function authorizeModifyDn(
        ModifyDnRequest $request,
        TokenInterface $token,
    ): void {
        $this->accessControl->authorizeOperation(
            OperationType::ModifyDn,
            $token,
            $request->getDn(),
        );

        $newParentDn = $request->getNewParentDn();

        if ($newParentDn === null) {
            return;
        }

        $this->accessControl->authorizeOperation(
            OperationType::ModifyDn,
            $token,
            $newParentDn,
        );
    }

    /**
     * @throws OperationException
     */
    private function authorizeWriteAttributes(
        RequestInterface $request,
        TokenInterface $token,
    ): void {
        if ($request instanceof AddRequest) {
            $dn = $request->getEntry()->getDn();
            foreach ($request->getEntry()->getAttributes() as $attribute) {
                $this->accessControl->authorizeAttribute(
                    $token,
                    $dn,
                    $attribute->getName(),
                );
            }

            return;
        }

        if ($request instanceof ModifyRequest) {
            $dn = $request->getDn();
            foreach ($request->getChanges() as $change) {
                $this->accessControl->authorizeAttribute(
                    $token,
                    $dn,
                    $change->getAttribute()->getName(),
                );
            }
        }
    }

    /**
     * Authorizes any privileged control attached to a write before it is dispatched.
     *
     * @throws OperationException
     */
    private function authorizeControls(
        RequestInterface $request,
        ControlBag $controls,
        TokenInterface $token,
    ): void {
        $dn = $this->dnFor($request);

        if ($dn === null) {
            return;
        }

        foreach (self::PRIVILEGED_CONTROLS as $oid) {
            if (!$controls->has($oid)) {
                continue;
            }

            $this->accessControl->authorizeControl(
                $token,
                $dn,
                $oid,
            );
        }
    }

    private function dnFor(RequestInterface $request): ?Dn
    {
        return match (true) {
            $request instanceof AddRequest => $request->getEntry()->getDn(),
            $request instanceof ModifyRequest,
            $request instanceof DeleteRequest,
            $request instanceof ModifyDnRequest,
            $request instanceof CompareRequest => $request->getDn(),
            default => null,
        };
    }
}
