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
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\ResponseAlreadySentException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authorization\DispatchAuthorizer;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
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
        private readonly MiddlewareHandlerInterface $requestPipeline,
        private readonly ServerAuthorization $authorizer,
        private readonly Authenticator $authenticator,
        private readonly DispatchAuthorizer $dispatchAuthorizer,
        private readonly EventLogger $eventLogger = new EventLogger(null),
        private readonly ResponseFactory $responseFactory = new ResponseFactory(),
        private readonly ConnectionContext $connectionContext = new ConnectionContext(),
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
        } catch (ResponseAlreadySentException $e) {
            # The handler already sent the response (e.g. SASL, which needs the correct multi-round message ID), so
            # only the audit log below applies here.
            $this->logCriticalControlRejection(
                $e,
                $message,
            );
        } catch (OperationException $e) {
            # OperationExceptions may be thrown by any handler and will be sent back to the client as the response
            # specific error code and message associated with the exception.
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                $e->getCode(),
                $e->getMessage(),
            ));

            $this->logCriticalControlRejection(
                $e,
                $message,
            );
        } catch (ConnectionException) {
            # Connection closure is recorded by the runner's lifecycle logging; no audit event for normal client disconnects.
        } catch (EncoderException|ProtocolException) {
            # Per RFC 4511 §4.1.1, a PDU that cannot be processed — malformed, or rejected for exceeding the configured
            # size cap (RequestSizeExceededException) — warrants a disconnect with a protocol error. The
            # NoticeOfDisconnectSent event records the specific reason.
            $this->sendNoticeOfDisconnect('The message could not be processed.');
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

        $authorization = $this->dispatchAuthorizer->authorize($message);

        if ($authorization->requiresAuthentication()) {
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                'Authentication required.',
            ));

            return;
        }

        if ($authorization->requiresPasswordChange()) {
            $this->rejectUntilPasswordChanged($message);

            return;
        }

        # A pipeline gate (critical-control, authorization, assertion) rejects per-operation by throwing
        # We need to catch here and send the response.
        try {
            $this->requestPipeline->handle(new ServerRequestContext(
                $message,
                $authorization->token(),
                $this->connectionContext,
            ));
        } catch (OperationException $e) {
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                $e->getCode(),
                $e->getMessage(),
            ));
            $this->logCriticalControlRejection(
                $e,
                $message,
            );
        }
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
     * Handlers without their own catch (StartTLS, WhoAmI, RootDse, etc.) only reach the audit log via this path.
     *
     * Critical-control rejection is the realistic case; other codes are direction-dependent or already covered.
     */
    private function logCriticalControlRejection(
        OperationException $exception,
        ?LdapMessageRequest $message,
    ): void {
        if ($exception->getCode() !== ResultCode::UNAVAILABLE_CRITICAL_EXTENSION) {
            return;
        }

        $this->eventLogger->recordFailure(
            ServerEvent::CriticalControlRejected,
            $exception,
            subject: $this->authorizer->getToken(),
            message: $message,
        );
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
