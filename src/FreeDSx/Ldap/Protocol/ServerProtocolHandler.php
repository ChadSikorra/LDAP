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

namespace FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordResetGate;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Socket\Exception\ConnectionException;
use Throwable;

use function in_array;

/**
 * Handles server-client specific protocol interactions.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerProtocolHandler
{
    /**
     * @var int[]
     */
    private array $messageIds = [];

    public function __construct(
        private readonly ServerQueue $queue,
        private readonly ServerProtocolHandlerFactory $protocolHandlerFactory,
        private readonly ServerAuthorization $authorizer,
        private readonly Authenticator $authenticator,
        private readonly EventLogger $eventLogger = new EventLogger(null),
        private readonly ResponseFactory $responseFactory = new ResponseFactory(),
        private readonly ?PasswordPolicyContext $passwordPolicyContext = null,
        private readonly PasswordResetGate $passwordResetGate = new PasswordResetGate(),
    ) {}

    /**
     * Listens for messages from the socket and handles the responses/actions needed.
     *
     * @throws EncoderException
     */
    public function handle(): void
    {
        $message = null;

        try {
            while ($message = $this->queue->getMessage()) {
                $this->dispatchRequest($message);
                # If a protocol handler closed the TCP connection, then just break here...
                if (!$this->queue->isConnected()) {
                    break;
                }
            }
        } catch (OperationException $e) {
            # OperationExceptions may be thrown by any handler and will be sent back to the client as the response
            # specific error code and message associated with the exception.
            $control = $this->passwordPolicyControlFor($message);
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                $e->getCode(),
                $e->getMessage(),
                null,
                ...($control === null ? [] : [$control]),
            ));

            # Handlers without their own catch (StartTLS, WhoAmI, RootDse, etc.) only reach the audit log via this catch.
            # Critical-control rejection is the realistic case; other codes are direction-dependent or already covered.
            if ($e->getCode() === ResultCode::UNAVAILABLE_CRITICAL_EXTENSION) {
                $this->eventLogger->recordFailure(
                    ServerEvent::CriticalControlRejected,
                    $e,
                    [],
                    subject: $this->authorizer->getToken(),
                    message: $message,
                );
            }
        } catch (ConnectionException) {
            # Connection closure is recorded by the runner's lifecycle logging; no audit event for normal client disconnects.
        } catch (EncoderException|ProtocolException) {
            # Per RFC 4511, 4.1.1 if the PDU cannot be parsed or is otherwise malformed a disconnect should be sent with
            # a result code of protocol error. The NoticeOfDisconnectSent event records the malformed-PDU reason.
            $this->sendNoticeOfDisconnect('The message encoding is malformed.');
        } catch (Throwable $e) {
            if ($this->queue->isConnected()) {
                $this->sendNoticeOfDisconnect(cause: $e);
            }
        } finally {
            if ($this->queue->isConnected()) {
                $this->queue->close();
            }
        }
    }

    /**
     * Used asynchronously to end a client session when the server process is shutting down.
     *
     * @throws EncoderException
     */
    public function shutdown(): void
    {
        $this->sendNoticeOfDisconnect(
            'The server is shutting down.',
            ResultCode::UNAVAILABLE,
        );
        $this->queue->close();
    }

    /**
     * Routes requests from the message queue based off the current authorization state and what protocol handler the
     * request is mapped to.
     *
     * @throws OperationException
     * @throws EncoderException
     * @throws RuntimeException
     * @throws ConnectionException
     */
    private function dispatchRequest(LdapMessageRequest $message): void
    {
        if (!$this->isValidRequest($message)) {
            return;
        }

        $this->messageIds[] = $message->getMessageId();

        # Send auth requests to the specific handler for it...
        if ($this->authorizer->isAuthenticationRequest($message->getRequest())) {
            $this->authorizer->setToken($this->handleAuthRequest($message));

            return;
        }
        $request = $message->getRequest();
        $handler = $this->protocolHandlerFactory->get(
            $request,
            $message->controls(),
        );

        # They are authenticated or authentication is not required, so pass the request along...
        if ($this->authorizer->isAuthenticated() || !$this->authorizer->isAuthenticationRequired($request)) {
            if ($this->requiresPasswordChangeFirst($request)) {
                $this->rejectUntilPasswordChanged($message);

                return;
            }

            $handler->handleRequest(
                $message,
                $this->authorizer->getToken(),
            );
            # Authentication is required, but they have not authenticated...
        } else {
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                'Authentication required.',
            ));
        }
    }

    /**
     * A bound identity flagged with pwdReset may only change its password or end the session (draft-behera-10 §8.1.2).
     */
    private function requiresPasswordChangeFirst(RequestInterface $request): bool
    {
        $token = $this->authorizer->getToken();

        return $token instanceof AuthenticatedTokenInterface
            && $token->mustChangePassword()
            && !$this->passwordResetGate->isPermitted($request, $token);
    }

    /**
     * @throws EncoderException
     */
    private function rejectUntilPasswordChanged(LdapMessageRequest $message): void
    {
        $this->queue->sendMessage($this->responseFactory->getStandardResponse(
            $message,
            ResultCode::UNWILLING_TO_PERFORM,
            'The password must be changed before any other operation is permitted.',
            null,
            new PwdPolicyResponseControl(error: PwdPolicyError::CHANGE_AFTER_RESET),
        ));
    }

    /**
     * Checks that the message ID is valid. It cannot be zero or a message ID that was already used.
     *
     * @throws EncoderException
     * @throws EncoderException
     */
    private function isValidRequest(LdapMessageRequest $message): bool
    {
        if ($message->getMessageId() === 0) {
            $this->queue->sendMessage($this->responseFactory->getExtendedError(
                'The message ID 0 cannot be used in a client request.',
                ResultCode::PROTOCOL_ERROR,
            ));

            return false;
        }
        if (in_array($message->getMessageId(), $this->messageIds, true)) {
            $this->queue->sendMessage($this->responseFactory->getExtendedError(
                sprintf('The message ID %s is not valid.', $message->getMessageId()),
                ResultCode::PROTOCOL_ERROR,
            ));

            return false;
        }

        return true;
    }

    /**
     * Sends a bind request to the bind handler and returns the token.
     *
     * @throws OperationException
     * @throws RuntimeException
     */
    private function handleAuthRequest(LdapMessageRequest $message): TokenInterface
    {
        if (!$this->authorizer->isAuthenticationTypeSupported($message->getRequest())) {
            throw new OperationException(
                'The requested authentication type is not supported.',
                ResultCode::AUTH_METHOD_UNSUPPORTED,
            );
        }

        return $this->authenticator->bind($message);
    }

    /**
     * Password-policy response control for a failed bind; null for non-bind failures or when no policy is in play.
     */
    private function passwordPolicyControlFor(?LdapMessageRequest $message): ?Control
    {
        if (!$this->shouldAttachPolicyControl($message)) {
            return null;
        }

        $control = $this->passwordPolicyContext?->buildResponseControl();
        $this->passwordPolicyContext?->clear();

        return $control;
    }

    private function shouldAttachPolicyControl(?LdapMessageRequest $message): bool
    {
        return $this->passwordPolicyContext !== null
            && $message !== null
            && $this->authorizer->isAuthenticationRequest($message->getRequest());
    }

    /**
     * @throws EncoderException
     */
    private function sendNoticeOfDisconnect(
        string $message = '',
        int $reasonCode = ResultCode::PROTOCOL_ERROR,
        ?Throwable $cause = null,
    ): void {
        $this->queue->sendMessage($this->responseFactory->getExtendedError(
            $message,
            $reasonCode,
            ExtendedResponse::OID_NOTICE_OF_DISCONNECTION,
        ));
        $this->eventLogger->record(
            ServerEvent::NoticeOfDisconnectSent,
            [
                EventContext::REASON_CODE => $reasonCode,
                EventContext::REASON_MESSAGE => $message,
            ] + $this->eventLogger->exceptionContextFor($cause),
        );
    }
}
