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
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\SchemaViolations;
use FreeDSx\Ldap\Server\Backend\Write\WriteCommandFactory;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Operation\CompareOperationResult;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use FreeDSx\Ldap\Server\Operation\WriteOperationResult;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles generic requests that are dispatched to the backend.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerDispatchHandler implements ServerProtocolHandlerInterface
{
    use MatchedDnAccessFilterTrait;

    public function __construct(
        private ServerQueue $queue,
        private LdapBackendInterface $backend,
        private WriteOperationDispatcher $writeDispatcher,
        private AccessControlInterface $accessControl,
        private WriteCommandFactory $commandFactory = new WriteCommandFactory(),
        private ResponseFactory $responseFactory = new ResponseFactory(),
        private ?PasswordPolicyContext $passwordPolicyContext = null,
    ) {}

    /**
     * {@inheritDoc}
     *
     * @throws EncoderException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): OperationResult {
        $this->passwordPolicyContext?->clear();
        $schemaViolations = new SchemaViolations();

        try {
            $request = $message->getRequest();

            if ($request instanceof Request\CompareRequest) {
                $match = $this->backend->compare($request->getDn(), $request->getFilter());
                $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                    $message,
                    $match
                        ? ResultCode::COMPARE_TRUE
                        : ResultCode::COMPARE_FALSE,
                ));

                return CompareOperationResult::completed(
                    $message,
                    $match,
                );
            }

            $this->writeDispatcher->dispatch(
                $this->commandFactory->fromRequest($request),
                new WriteContext(
                    $token,
                    $message->controls(),
                    schemaViolations: $schemaViolations,
                ),
            );

            $successControl = $this->passwordPolicyControl();
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                ResultCode::SUCCESS,
                '',
                null,
                ...($successControl === null ? [] : [$successControl]),
            ));

            return WriteOperationResult::success(
                $message,
                $schemaViolations,
            );
        } catch (OperationException $e) {
            $errorControl = $this->passwordPolicyControl();
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                $e->getCode(),
                $e->getMessage(),
                $this->filterMatchedDn(
                    $e->getMatchedDn(),
                    $token,
                    $this->backend,
                    $this->accessControl,
                ),
                ...($errorControl === null ? [] : [$errorControl]),
            ));

            return WriteOperationResult::failure(
                $message,
                $e,
                $schemaViolations,
            );
        }
    }

    private function passwordPolicyControl(): ?Control
    {
        $control = $this->passwordPolicyContext?->buildResponseControl();
        $this->passwordPolicyContext?->clear();

        return $control;
    }
}
