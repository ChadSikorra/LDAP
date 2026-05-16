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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Server\AccessControl\OperationType;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Builds the per-operation event shape for {@see ServerDispatchHandler} and routes it through {@see EventLogger}.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class DispatchEventRecorder
{
    public function __construct(private EventLogger $eventLogger) {}

    public function recordWriteSuccess(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): void {
        $request = $message->getRequest();
        $operationType = OperationType::fromRequest($request);

        if ($operationType === null) {
            return;
        }

        $event = ServerEvent::fromWriteOperationType($operationType);

        if ($event === null) {
            return;
        }

        $this->eventLogger->record(
            $event,
            [
                EventContext::OPERATION => $operationType->value,
                EventContext::TARGET => $this->writeTargetFor($request),
            ],
            subject: $token,
            message: $message,
        );
    }

    public function recordCompareCompleted(
        LdapMessageRequest $message,
        bool $match,
        TokenInterface $token,
    ): void {
        $request = $message->getRequest();

        if (!$request instanceof CompareRequest) {
            return;
        }

        $this->eventLogger->record(
            ServerEvent::CompareCompleted,
            [
                EventContext::MATCH => $match,
                EventContext::TARGET => [
                    EventContext::DN => $request->getDn()->toString(),
                    EventContext::ATTRIBUTE => $request->getFilter()->getAttribute(),
                ],
            ],
            subject: $token,
            message: $message,
        );
    }

    public function recordFailure(
        LdapMessageRequest $message,
        OperationException $exception,
        TokenInterface $token,
    ): void {
        $event = ServerEvent::fromOperationException(
            $exception,
            ServerEvent::AuthorizationDeniedWrite,
        );

        if ($event === null) {
            return;
        }

        $request = $message->getRequest();
        $context = [EventContext::TARGET => $this->writeTargetFor($request)];
        $operationType = OperationType::fromRequest($request);

        if ($operationType !== null) {
            $context[EventContext::OPERATION] = $operationType->value;
        }

        $this->eventLogger->recordFailure(
            $event,
            $exception,
            $context,
            subject: $token,
            message: $message,
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function writeTargetFor(RequestInterface $request): array
    {
        if ($request instanceof ModifyDnRequest) {
            return $this->modifyDnTarget($request);
        }

        return [EventContext::DN => $this->dnFor($request)?->toString() ?? ''];
    }

    /**
     * @return array<string, mixed>
     */
    private function modifyDnTarget(ModifyDnRequest $request): array
    {
        $target = [
            EventContext::DN => $request->getDn()->toString(),
            EventContext::NEW_RDN => $request->getNewRdn()->toString(),
        ];
        $newSuperior = $request->getNewParentDn();

        if ($newSuperior !== null) {
            $target[EventContext::NEW_SUPERIOR_DN] = $newSuperior->toString();
        }

        return $target;
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
