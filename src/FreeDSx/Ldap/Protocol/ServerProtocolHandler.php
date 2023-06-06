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

use Exception;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\LoggerTrait;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\Factory\ServerBindHandlerFactory;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\RequestHistory;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Exception\ConnectionException;
use Throwable;
use function array_merge;
use function in_array;

/**
 * Handles server-client specific protocol interactions.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerProtocolHandler
{
    use LoggerTrait;

    private ServerOptions $options;

    private ServerQueue $queue;

    /**
     * @var int[]
     */
    private array $messageIds = [];

    private HandlerFactoryInterface $handlerFactory;

    private ServerAuthorization $authorizer;

    private ServerProtocolHandlerFactory $protocolHandlerFactory;

    private ResponseFactory $responseFactory;

    private ServerBindHandlerFactory $bindHandlerFactory;

    public function __construct(
        ServerQueue $queue,
        HandlerFactoryInterface $handlerFactory,
        ServerOptions $options,
        ServerProtocolHandlerFactory $protocolHandlerFactory = null,
        ServerBindHandlerFactory $bindHandlerFactory = new ServerBindHandlerFactory(),
        ServerAuthorization $authorizer = null,
        ResponseFactory $responseFactory = new ResponseFactory()
    ) {
        $this->queue = $queue;
        $this->handlerFactory = $handlerFactory;
        $this->options = $options;
        $this->authorizer = $authorizer ?? new ServerAuthorization(
            isAnonymousAllowed: $options->isAllowAnonymous(),
            isAuthRequired: $options->isRequireAuthentication(),
        );
        $this->protocolHandlerFactory = $protocolHandlerFactory ?? new ServerProtocolHandlerFactory(
            handlerFactory: $handlerFactory,
            requestHistory: new RequestHistory(),
        );
        $this->bindHandlerFactory = $bindHandlerFactory;
        $this->responseFactory = $responseFactory;
    }

    /**
     * Listens for messages from the socket and handles the responses/actions needed.
     *
     * @throws EncoderException
     */
    public function handle(array $defaultContext = []): void
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
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                $e->getCode(),
                $e->getMessage()
            ));
        } catch (ConnectionException $e) {
            $this->logInfo(
                'Ending LDAP client due to client connection issues.',
                array_merge(
                    ['message' => $e->getMessage()],
                    $defaultContext
                )
            );
        } catch (EncoderException | ProtocolException) {
            # Per RFC 4511, 4.1.1 if the PDU cannot be parsed or is otherwise malformed a disconnect should be sent with a
            # result code of protocol error.
            $this->sendNoticeOfDisconnect('The message encoding is malformed.');
            $this->logError(
                'The client sent a malformed request. Terminating their connection.',
                $defaultContext
            );
        } catch (Exception | Throwable $e) {
            $this->logError(
                'An unexpected exception was caught while handling the client. Terminating their connection.',
                array_merge(
                    $defaultContext,
                    ['exception' => $e]
                )
            );
            if ($this->queue->isConnected()) {
                $this->sendNoticeOfDisconnect();
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
    public function shutdown(array $context = []): void
    {
        $this->sendNoticeOfDisconnect(
            'The server is shutting down.',
            ResultCode::UNAVAILABLE
        );
        $this->queue->close();
        $this->logInfo(
            'Sent notice of disconnect to client and closed the connection.',
            $context
        );
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
            $message->controls()
        );

        # They are authenticated or authentication is not required, so pass the request along...
        if ($this->authorizer->isAuthenticated() || !$this->authorizer->isAuthenticationRequired($request)) {
            $handler->handleRequest(
                $message,
                $this->authorizer->getToken(),
                $this->handlerFactory->makeRequestHandler(),
                $this->queue,
                $this->options
            );
        # Authentication is required, but they have not authenticated...
        } else {
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                'Authentication required.'
            ));
        }
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
                ResultCode::PROTOCOL_ERROR
            ));

            return false;
        }
        if (in_array($message->getMessageId(), $this->messageIds, true)) {
            $this->queue->sendMessage($this->responseFactory->getExtendedError(
                sprintf('The message ID %s is not valid.', $message->getMessageId()),
                ResultCode::PROTOCOL_ERROR
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
                ResultCode::AUTH_METHOD_UNSUPPORTED
            );
        }

        return $this->bindHandlerFactory->get($message->getRequest())->handleBind(
            $message,
            $this->handlerFactory->makeRequestHandler(),
            $this->queue
        );
    }

    /**
     * @throws EncoderException
     */
    private function sendNoticeOfDisconnect(
        string $message = '',
        int $reasonCode = ResultCode::PROTOCOL_ERROR
    ): void {
        $this->queue->sendMessage($this->responseFactory->getExtendedError(
            $message,
            $reasonCode,
            ExtendedResponse::OID_NOTICE_OF_DISCONNECTION
        ));
    }
}
