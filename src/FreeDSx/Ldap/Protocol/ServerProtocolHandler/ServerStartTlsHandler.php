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
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Exception\ConnectionException;

use function extension_loaded;

/**
 * Handles StartTLS logic.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerStartTlsHandler implements ServerProtocolHandlerInterface
{
    private static ?bool $hasOpenssl = null;

    public function __construct(
        private readonly ServerOptions $options,
        private readonly ServerQueue $queue,
        private readonly EventLogger $eventLogger = new EventLogger(null),
    ) {
        if (self::$hasOpenssl === null) {
            $this::$hasOpenssl = extension_loaded('openssl');
        }
    }

    /**
     * {@inheritDoc}
     * @throws ConnectionException
     * @throws EncoderException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): OperationResult {
        # RFC 4511 §4.14.2: return unavailable (not protocolError) when the server cannot negotiate TLS.
        if ($this->options->getSslCert() === null || !self::$hasOpenssl) {
            $this->queue->sendMessage(new LdapMessageResponse($message->getMessageId(), new ExtendedResponse(
                new LdapResult(
                    ResultCode::UNAVAILABLE,
                    '',
                    'The server is not configured to provide TLS.',
                ),
                ExtendedRequest::OID_START_TLS,
            )));
            $this->eventLogger->record(
                ServerEvent::StartTlsFailed,
                [
                    EventContext::RESULT_CODE => ResultCode::UNAVAILABLE,
                    EventContext::REASON => 'The server is not configured to provide TLS.',
                ],
                message: $message,
            );

            return OperationOutcomeResult::failed(ResultCode::UNAVAILABLE);
        }
        # If we are already encrypted, then consider this an operations error...
        if ($this->queue->isEncrypted()) {
            $this->queue->sendMessage(new LdapMessageResponse($message->getMessageId(), new ExtendedResponse(
                new LdapResult(ResultCode::OPERATIONS_ERROR, '', 'The current LDAP session is already encrypted.'),
                ExtendedRequest::OID_START_TLS,
            )));
            $this->eventLogger->record(
                ServerEvent::StartTlsFailed,
                [
                    EventContext::RESULT_CODE => ResultCode::OPERATIONS_ERROR,
                    EventContext::REASON => 'The current LDAP session is already encrypted.',
                ],
                message: $message,
            );

            return OperationOutcomeResult::failed(ResultCode::OPERATIONS_ERROR);
        }

        $this->queue->sendMessage(new LdapMessageResponse($message->getMessageId(), new ExtendedResponse(
            new LdapResult(ResultCode::SUCCESS),
            ExtendedRequest::OID_START_TLS,
        )));
        $this->queue->encrypt();
        $this->eventLogger->record(
            ServerEvent::StartTlsSucceeded,
            message: $message,
        );

        return OperationOutcomeResult::succeeded();
    }
}
