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

namespace Tests\Unit\FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\ResponseAlreadySentException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\ModifyDnResponse;
use FreeDSx\Ldap\Operation\Response\ModifyResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authenticator;
use FreeDSx\Ldap\Protocol\Authorization\DispatchAuthorizer;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Exception\ConnectionException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;

final class ServerProtocolHandlerTest extends TestCase
{
    private ServerProtocolHandler $subject;

    private ServerQueue&MockObject $mockQueue;

    private ServerProtocolHandlerFactory&MockObject $mockProtocolHandlerFactory;

    private Authenticator&MockObject $mockAuthenticator;

    private ServerProtocolHandler\ServerProtocolHandlerInterface&MockObject $mockProtocolHandler;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockProtocolHandlerFactory = $this->createMock(ServerProtocolHandlerFactory::class);
        $this->mockAuthenticator = $this->createMock(Authenticator::class);
        $this->mockProtocolHandler = $this->createMock(ServerProtocolHandler\ServerProtocolHandlerInterface::class);

        $this->mockQueue
            ->method('isConnected')
            ->willReturn(true);
        $this->mockQueue
            ->method('isEncrypted')
            ->willReturn(false);

        $this->mockQueue
            ->method('sendMessage')
            ->willReturnSelf();

        $this->mockProtocolHandlerFactory
            ->method('get')
            ->willReturn($this->mockProtocolHandler);

        $authorizer = new ServerAuthorization(new ServerOptions());
        $this->subject = new ServerProtocolHandler(
            $this->mockQueue,
            $this->mockProtocolHandlerFactory,
            $authorizer,
            $this->mockAuthenticator,
            new DispatchAuthorizer($authorizer),
        );
    }

    public function test_it_should_enforce_anonymous_bind_requirements(): void
    {
        $messages = [new LdapMessageRequest(1, new AnonBindRequest('foo'))];
        $this->mockQueue
            ->method('getMessage')
            ->willReturnCallback(static function () use (&$messages): LdapMessageRequest {
                if ($messages === []) {
                    throw new ConnectionException();
                }

                return array_shift($messages);
            });

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with($this->equalTo(
                new LdapMessageResponse(
                    1,
                    new BindResponse(new LdapResult(
                        ResultCode::AUTH_METHOD_UNSUPPORTED,
                        '',
                        'The requested authentication type is not supported.',
                    )),
                ),
            ));

        $this->mockProtocolHandlerFactory
            ->expects(self::never())
            ->method('get');

        $this->subject->handle();
    }

    public function test_it_should_not_allow_a_previous_message_ID_from_a_new_request(): void
    {
        $messages = [
            new LdapMessageRequest(1, new SimpleBindRequest('foo', 'bar')),
            new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_WHOAMI)),
        ];
        $this->mockQueue
            ->method('getMessage')
            ->willReturnCallback(static function () use (&$messages): LdapMessageRequest {
                if ($messages === []) {
                    throw new ConnectionException();
                }

                return array_shift($messages);
            });

        $this->mockAuthenticator
            ->method('bind')
            ->willReturn(BindToken::fromDn(
                'foo',
                'bar',
            ));

        $this->mockProtocolHandler
            ->expects($this->never())
            ->method('handleRequest');

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with($this->equalTo(new LdapMessageResponse(
                0,
                new ExtendedResponse(new LdapResult(
                    ResultCode::PROTOCOL_ERROR,
                    '',
                    'The message ID 1 is not valid.',
                )),
            )));

        $this->subject->handle();
    }

    public function test_it_should_enforce_authentication_requirements(): void
    {
        $this->mockQueue
            ->method('isConnected')
            ->willReturn(true);
        $messages = [
            new LdapMessageRequest(1, new ModifyDnRequest('cn=foo,dc=bar', 'cn=bar', true)),
        ];
        $this->mockQueue
            ->method('getMessage')
            ->willReturnCallback(static function () use (&$messages): LdapMessageRequest {
                if ($messages === []) {
                    throw new ConnectionException();
                }

                return array_shift($messages);
            });

        $this->mockQueue
            ->expects($this->atLeast(1))
            ->method('sendMessage')
            ->with($this->equalTo(new LdapMessageResponse(
                1,
                new ModifyDnResponse(
                    ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                    '',
                    'Authentication required.',
                ),
            )))
            ->willReturnSelf();

        $this->mockProtocolHandler
            ->expects($this->never())
            ->method('handleRequest');

        $this->subject->handle();
    }

    public function test_it_should_send_a_notice_of_disconnect_on_a_protocol_exception_from_the_message_queue(): void
    {
        $this->mockQueue
            ->method('getMessage')
            ->willThrowException(new ProtocolException());

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with($this->equalTo(
                new LdapMessageResponse(0, new ExtendedResponse(
                    new LdapResult(ResultCode::PROTOCOL_ERROR, '', 'The message encoding is malformed.'),
                    ExtendedResponse::OID_NOTICE_OF_DISCONNECTION,
                )),
            ));

        $this->subject->handle();
    }

    public function test_it_should_handle_a_socket_exception_from_the_message_queue_and_end_normally(): void
    {
        $this->mockQueue
            ->method('getMessage')
            ->willThrowException(new ConnectionException("Foo"));

        $this->mockQueue
            ->expects($this->never())
            ->method('sendMessage');

        $this->subject->handle();
    }

    public function test_it_should_send_a_notice_of_disconnect_on_an_encoder_exception_from_the_message_queue(): void
    {
        $this->mockQueue
            ->method('getMessage')
            ->willThrowException(new EncoderException());

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with($this->equalTo(
                new LdapMessageResponse(0, new ExtendedResponse(
                    new LdapResult(ResultCode::PROTOCOL_ERROR, '', 'The message encoding is malformed.'),
                    ExtendedResponse::OID_NOTICE_OF_DISCONNECTION,
                )),
            ));

        $this->subject->handle();
    }

    public function test_it_should_not_allow_a_message_with_an_ID_of_zero(): void
    {
        $messages = [
            new LdapMessageRequest(0, new ExtendedRequest(ExtendedRequest::OID_START_TLS)),
        ];
        $this->mockQueue
            ->method('getMessage')
            ->willReturnCallback(static function () use (&$messages): LdapMessageRequest {
                if ($messages === []) {
                    throw new ConnectionException();
                }

                return array_shift($messages);
            });

        $this->mockQueue
            ->expects($this->atLeast(1))
            ->method('sendMessage')
            ->with($this->equalTo(
                new LdapMessageResponse(0, new ExtendedResponse(new LdapResult(
                    ResultCode::PROTOCOL_ERROR,
                    '',
                    'The message ID 0 cannot be used in a client request.',
                ))),
            ));

        $this->subject->handle();
    }

    public function test_it_should_send_a_bind_request_to_the_bind_request_handler(): void
    {
        $messages = [
            new LdapMessageRequest(1, new SimpleBindRequest('foo@bar', 'bar')),
        ];
        $this->mockQueue
            ->method('getMessage')
            ->willReturnCallback(static function () use (&$messages): LdapMessageRequest {
                if ($messages === []) {
                    throw new ConnectionException();
                }

                return array_shift($messages);
            });

        $this->mockAuthenticator
            ->expects($this->once())
            ->method('bind')
            ->willReturn(BindToken::fromDn(
                'foo@bar',
                'bar',
            ));

        $this->mockProtocolHandler
            ->expects($this->never())
            ->method('handleRequest');

        $this->subject->handle();
    }

    public function test_it_does_not_resend_when_a_handler_already_sent_the_response(): void
    {
        $messages = [
            new LdapMessageRequest(1, new SimpleBindRequest('foo@bar', 'bar')),
        ];
        $this->mockQueue
            ->method('getMessage')
            ->willReturnCallback(static function () use (&$messages): LdapMessageRequest {
                if ($messages === []) {
                    throw new ConnectionException();
                }

                return array_shift($messages);
            });

        $this->mockAuthenticator
            ->method('bind')
            ->willThrowException(new ResponseAlreadySentException(
                'Invalid credentials.',
                ResultCode::INVALID_CREDENTIALS,
            ));

        $this->mockQueue
            ->expects(self::never())
            ->method('sendMessage');

        $this->subject->handle();
    }

    public function test_it_should_handle_operation_errors_thrown_from_the_request_handlers(): void
    {
        $this->mockQueue
            ->method('isConnected')
            ->willReturnOnConsecutiveCalls(true, false);

        $messages = [
            new LdapMessageRequest(1, new SimpleBindRequest('foo@bar', 'bar')),
            new LdapMessageRequest(2, new ModifyRequest('cn=foo,dc=bar')),
        ];
        $this->mockQueue
            ->method('getMessage')
            ->willReturnCallback(static function () use (&$messages): LdapMessageRequest {
                if ($messages === []) {
                    throw new ConnectionException();
                }

                return array_shift($messages);
            });

        $this->mockAuthenticator
            ->expects($this->once())
            ->method('bind')
            ->willReturn(BindToken::fromDn(
                'foo@bar',
                'bar',
            ));

        $this->mockProtocolHandler
            ->expects($this->once())
            ->method('handleRequest')
            ->willThrowException(new OperationException(
                'Foo.',
                ResultCode::CONFIDENTIALITY_REQUIRED,
            ));

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with($this->equalTo(
                new LdapMessageResponse(
                    2,
                    new ModifyResponse(
                        ResultCode::CONFIDENTIALITY_REQUIRED,
                        '',
                        'Foo.',
                    ),
                ),
            ));

        $this->subject->handle();
    }

    public function test_it_should_send_a_notice_of_disconnect_and_close_the_queue_on_shutdown(): void
    {
        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with($this->equalTo(
                new LdapMessageResponse(0, new ExtendedResponse(
                    new LdapResult(ResultCode::UNAVAILABLE, '', 'The server is shutting down.'),
                    ExtendedResponse::OID_NOTICE_OF_DISCONNECTION,
                )),
            ));

        $this->mockQueue
            ->expects($this->once())
            ->method('close');

        $this->subject->shutdown();
    }

    public function test_unexpected_throwable_emits_notice_of_disconnect_with_exception_context(): void
    {
        $recordingLogger = new RecordingLogger();
        $subject = $this->makeSubjectWithEventLogger(new EventLogger(
            $recordingLogger,
            EventLogPolicy::default(),
        ));

        $this->mockQueue
            ->method('getMessage')
            ->willThrowException(new RuntimeException('boom'));

        $subject->handle();

        $disconnectRecord = $this->findRecord(
            $recordingLogger,
            'session.disconnect_notice',
        );
        self::assertSame(
            RuntimeException::class,
            $disconnectRecord['context']['exception_class'],
        );
        self::assertSame(
            'boom',
            $disconnectRecord['context']['exception_message'],
        );
        self::assertArrayHasKey(
            'exception_origin',
            $disconnectRecord['context'],
        );
        self::assertArrayNotHasKey(
            'exception_trace',
            $disconnectRecord['context'],
            'Trace must not appear with the default policy.',
        );
    }

    public function test_unexpected_throwable_includes_trace_when_policy_opts_in(): void
    {
        $recordingLogger = new RecordingLogger();
        $subject = $this->makeSubjectWithEventLogger(new EventLogger(
            $recordingLogger,
            EventLogPolicy::default()->withExceptionTraces(),
        ));

        $this->mockQueue
            ->method('getMessage')
            ->willThrowException(new RuntimeException('boom'));

        $subject->handle();

        $disconnectRecord = $this->findRecord(
            $recordingLogger,
            'session.disconnect_notice',
        );
        self::assertNotEmpty($disconnectRecord['context']['exception_trace']);
    }

    public function test_propagated_critical_control_rejection_emits_structured_event(): void
    {
        $recordingLogger = new RecordingLogger();
        $subject = $this->makeSubjectWithEventLogger(new EventLogger(
            $recordingLogger,
            EventLogPolicy::default(),
        ));

        $messages = [
            new LdapMessageRequest(7, new ExtendedRequest(ExtendedRequest::OID_START_TLS)),
        ];
        $this->mockQueue
            ->method('getMessage')
            ->willReturnCallback(static function () use (&$messages): LdapMessageRequest {
                if ($messages === []) {
                    throw new ConnectionException();
                }

                return array_shift($messages);
            });

        $this->mockProtocolHandler
            ->expects(self::once())
            ->method('handleRequest')
            ->willThrowException(new OperationException(
                'Critical control 1.2.3.4 is not supported.',
                ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
            ));

        $subject->handle();

        $record = $this->findRecord(
            $recordingLogger,
            'control.critical.rejected',
        );
        self::assertSame(
            7,
            $record['context']['message_id'],
        );
        self::assertSame(
            ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
            $record['context']['result_code'],
        );
    }

    public function test_a_must_change_token_blocks_other_operations(): void
    {
        $token = BindToken::fromDn(
            'cn=user,dc=foo,dc=bar',
            'secret',
        );
        $token->markMustChangePassword();

        $this->mockProtocolHandler
            ->expects(self::never())
            ->method('handleRequest');

        $captured = $this->runWithToken(
            $token,
            [
                new LdapMessageRequest(1, new SimpleBindRequest('cn=user,dc=foo,dc=bar', 'secret')),
                new LdapMessageRequest(2, new ModifyRequest(
                    'cn=user,dc=foo,dc=bar',
                    Change::replace('description', 'nope'),
                )),
            ],
        );

        self::assertCount(
            1,
            $captured,
        );
        $response = $captured[0]->getResponse();
        self::assertInstanceOf(
            LdapResult::class,
            $response,
        );
        self::assertSame(
            ResultCode::UNWILLING_TO_PERFORM,
            $response->getResultCode(),
        );

        $control = $captured[0]->controls()->getByClass(PwdPolicyResponseControl::class);
        self::assertInstanceOf(
            PwdPolicyResponseControl::class,
            $control,
        );
        self::assertSame(
            PwdPolicyError::CHANGE_AFTER_RESET,
            $control->getError(),
        );
    }

    public function test_a_must_change_token_allows_the_password_modify_operation(): void
    {
        $token = BindToken::fromDn(
            'cn=user,dc=foo,dc=bar',
            'secret',
        );
        $token->markMustChangePassword();

        $this->mockProtocolHandler
            ->expects(self::once())
            ->method('handleRequest');

        $this->runWithToken(
            $token,
            [
                new LdapMessageRequest(1, new SimpleBindRequest('cn=user,dc=foo,dc=bar', 'secret')),
                new LdapMessageRequest(2, new ExtendedRequest(ExtendedRequest::OID_PWD_MODIFY)),
            ],
        );
    }

    public function test_a_must_change_token_allows_a_self_password_modify(): void
    {
        $token = BindToken::fromDn(
            'cn=user,dc=foo,dc=bar',
            'secret',
        );
        $token->markMustChangePassword();

        $this->mockProtocolHandler
            ->expects(self::once())
            ->method('handleRequest');

        $this->runWithToken(
            $token,
            [
                new LdapMessageRequest(1, new SimpleBindRequest('cn=user,dc=foo,dc=bar', 'secret')),
                new LdapMessageRequest(2, new ModifyRequest(
                    'cn=user,dc=foo,dc=bar',
                    Change::replace('userPassword', 'a-fresh-password'),
                )),
            ],
        );
    }

    /**
     * @param list<LdapMessageRequest> $messages
     * @return list<LdapMessageResponse>
     */
    private function runWithToken(
        BindToken $token,
        array $messages,
    ): array {
        $captured = [];
        $queue = $this->createMock(ServerQueue::class);
        $queue
            ->method('isConnected')
            ->willReturn(true);
        $queue
            ->method('getMessage')
            ->willReturnCallback(static function () use (&$messages): LdapMessageRequest {
                if ($messages === []) {
                    throw new ConnectionException();
                }

                return array_shift($messages);
            });
        $queue
            ->method('sendMessage')
            ->willReturnCallback(function (LdapMessageResponse $response) use (&$captured, $queue): ServerQueue {
                $captured[] = $response;

                return $queue;
            });

        $this->mockAuthenticator
            ->method('bind')
            ->willReturn($token);

        $authorizer = new ServerAuthorization(new ServerOptions());
        $subject = new ServerProtocolHandler(
            $queue,
            $this->mockProtocolHandlerFactory,
            $authorizer,
            $this->mockAuthenticator,
            new DispatchAuthorizer($authorizer),
        );
        $subject->handle();

        return $captured;
    }

    private function makeSubjectWithEventLogger(EventLogger $eventLogger): ServerProtocolHandler
    {
        $authorizer = new ServerAuthorization(new ServerOptions());

        return new ServerProtocolHandler(
            $this->mockQueue,
            $this->mockProtocolHandlerFactory,
            $authorizer,
            $this->mockAuthenticator,
            new DispatchAuthorizer($authorizer),
            $eventLogger,
        );
    }

    /**
     * @return array{level: string, message: string, context: array<string, mixed>}
     */
    private function findRecord(
        RecordingLogger $logger,
        string $event,
    ): array {
        foreach ($logger->records as $record) {
            if ($record['message'] === $event) {
                return $record;
            }
        }

        self::fail(sprintf('No record found for event "%s".', $event));
    }
}
