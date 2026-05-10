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

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\OperationType;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteCommandFactory;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles generic requests that are dispatched to the backend.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerDispatchHandler implements ServerProtocolHandlerInterface
{
    public function __construct(
        private ServerQueue $queue,
        private LdapBackendInterface $backend,
        private WriteOperationDispatcher $writeDispatcher,
        private AccessControlInterface $accessControl,
        private WriteCommandFactory $commandFactory = new WriteCommandFactory(),
        private ResponseFactory $responseFactory = new ResponseFactory(),
    ) {}

    /**
     * {@inheritDoc}
     *
     * @throws EncoderException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): void {
        try {
            $request = $message->getRequest();
            $this->authorizeRequest(
                $request,
                $token,
            );
            $this->authorizeWriteAttributes(
                $request,
                $token,
            );

            if ($request instanceof Request\CompareRequest) {
                $this->accessControl->authorizeAttribute(
                    $token,
                    $request->getDn(),
                    $request->getFilter()->getAttribute(),
                );
                $match = $this->backend->compare($request->getDn(), $request->getFilter());
                $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                    $message,
                    $match
                        ? ResultCode::COMPARE_TRUE
                        : ResultCode::COMPARE_FALSE,
                ));

                return;
            }

            $this->writeDispatcher->dispatch(
                $this->commandFactory->fromRequest($request),
                new WriteContext(
                    $token,
                    $message->controls(),
                ),
            );

            $this->queue->sendMessage($this->responseFactory->getStandardResponse($message));
        } catch (OperationException $e) {
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                $e->getCode(),
                $e->getMessage(),
            ));
        }
    }

    /**
     * @throws OperationException
     */
    private function authorizeWriteAttributes(
        RequestInterface $request,
        TokenInterface $token,
    ): void {
        if ($request instanceof Request\AddRequest) {
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

        if ($request instanceof Request\ModifyRequest) {
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
     * @throws OperationException
     */
    private function authorizeRequest(
        RequestInterface $request,
        TokenInterface $token,
    ): void {
        if ($request instanceof Request\ModifyDnRequest) {
            $this->authorizeModifyDn(
                $request,
                $token,
            );

            return;
        }

        $result = match (true) {
            $request instanceof Request\CompareRequest => [OperationType::Compare, $request->getDn()],
            $request instanceof Request\AddRequest => [OperationType::Add, $request->getEntry()->getDn()],
            $request instanceof Request\DeleteRequest => [OperationType::Delete, $request->getDn()],
            $request instanceof Request\ModifyRequest => [OperationType::Modify, $request->getDn()],
            default => null,
        };

        if ($result === null) {
            return;
        }

        [$operationType, $dn] = $result;

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
        Request\ModifyDnRequest $request,
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
}
