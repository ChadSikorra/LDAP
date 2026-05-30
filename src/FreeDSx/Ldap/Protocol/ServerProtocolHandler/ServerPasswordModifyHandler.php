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
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use FreeDSx\Ldap\Server\Operation\PasswordModifyOperationResult;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyResult;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyService;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Adapts RFC 3062 Password Modify requests to {@see PasswordModifyService}: decode, delegate, encode the response.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerPasswordModifyHandler implements ServerProtocolHandlerInterface
{
    public function __construct(
        private ServerQueue $queue,
        private PasswordModifyService $service,
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
    ): OperationResult {
        $targetDn = null;

        try {
            $result = $this->changePassword(
                $message,
                $token,
            );
            $targetDn = $result->targetDn;
            $this->sendSuccess(
                $message,
                $result,
            );
        } catch (OperationException $e) {
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                $e->getCode(),
                $e->getMessage(),
            ));

            return PasswordModifyOperationResult::failure(
                $message,
                $e,
                $targetDn,
            );
        }

        return PasswordModifyOperationResult::success(
            $message,
            $targetDn,
        );
    }

    /**
     * @throws OperationException
     */
    private function changePassword(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): PasswordModifyResult {
        if (!$token instanceof AuthenticatedTokenInterface) {
            throw new OperationException(
                'Authentication required.',
                ResultCode::UNWILLING_TO_PERFORM,
            );
        }

        /** @var ExtendedRequest $raw */
        $raw = $message->getRequest();

        return $this->service->change(
            PasswordModifyRequest::fromAsn1($raw->toAsn1()),
            $token,
            $message->controls(),
        );
    }

    private function sendSuccess(
        LdapMessageRequest $message,
        PasswordModifyResult $result,
    ): void {
        $this->queue->sendMessage(new LdapMessageResponse(
            $message->getMessageId(),
            new PasswordModifyResponse(
                new LdapResult(ResultCode::SUCCESS),
                $result->generatedPassword,
            ),
        ));
    }
}
