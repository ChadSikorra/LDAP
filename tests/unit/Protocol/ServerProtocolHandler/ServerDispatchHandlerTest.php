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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerDispatchHandler;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestInterface;
use FreeDSx\Ldap\Server\Operation\CompareOperationResult;
use FreeDSx\Ldap\Server\Operation\OperationOutcome;
use FreeDSx\Ldap\Server\Operation\WriteOperationResult;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerDispatchHandlerTest extends TestCase
{
    private ServerDispatchHandler $subject;

    private LdapBackendInterface&MockObject $mockBackend;

    private WriteHandlerInterface&MockObject $mockWriteHandler;

    private ServerQueue&MockObject $mockQueue;

    private TokenInterface&MockObject $mockToken;

    private AccessControlInterface&MockObject $mockAccessControl;

    protected function setUp(): void
    {
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockBackend = $this->createMock(LdapBackendInterface::class);
        $this->mockWriteHandler = $this->createMock(WriteHandlerInterface::class);
        $this->mockAccessControl = $this->createMock(AccessControlInterface::class);

        $this->mockQueue
            ->method('sendMessage')
            ->willReturnSelf();

        $this->mockWriteHandler
            ->method('supports')
            ->willReturn(true);

        $this->subject = new ServerDispatchHandler(
            queue: $this->mockQueue,
            backend: $this->mockBackend,
            writeDispatcher: new WriteOperationDispatcher($this->mockWriteHandler),
            accessControl: $this->mockAccessControl,
            schema: new Schema(),
        );
    }

    public function test_it_dispatches_write_requests_through_the_write_handler(): void
    {
        $add = new LdapMessageRequest(1, new AddRequest(Entry::create('cn=foo,dc=bar')));

        $this->mockWriteHandler
            ->expects(self::once())
            ->method('handle')
            ->with(self::isInstanceOf(WriteRequestInterface::class));

        $result = $this->subject->handleRequest($add, $this->mockToken);

        self::assertInstanceOf(WriteOperationResult::class, $result);
        self::assertSame(
            OperationOutcome::Succeeded,
            $result->outcome(),
        );
    }

    public function test_it_sends_error_response_for_operation_exceptions_from_the_write_handler(): void
    {
        $add = new LdapMessageRequest(1, new AddRequest(Entry::create('cn=foo,dc=bar')));

        $this->mockWriteHandler
            ->method('handle')
            ->willThrowException(new OperationException(
                'Entry already exists.',
                ResultCode::ENTRY_ALREADY_EXISTS,
            ));

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::callback(function (LdapMessageResponse $msg): bool {
                return $msg->getResponse() instanceof LdapResult
                    && $msg->getResponse()->getResultCode() === ResultCode::ENTRY_ALREADY_EXISTS;
            }))
            ->willReturnSelf();

        $result = $this->subject->handleRequest($add, $this->mockToken);

        self::assertInstanceOf(WriteOperationResult::class, $result);
        self::assertSame(
            OperationOutcome::Failed,
            $result->outcome(),
        );
    }

    public function test_it_delegates_compare_to_the_backend(): void
    {
        $filter = Filters::equal('foo', 'bar');
        $compare = new LdapMessageRequest(1, new CompareRequest('cn=foo,dc=bar', $filter));

        $this->mockWriteHandler
            ->expects(self::never())
            ->method('handle');

        $this->mockBackend
            ->expects(self::once())
            ->method('compare')
            ->with(
                self::isInstanceOf(Dn::class),
                self::isInstanceOf(EqualityFilter::class),
            )
            ->willReturn(true);

        $result = $this->subject->handleRequest($compare, $this->mockToken);

        self::assertInstanceOf(CompareOperationResult::class, $result);
    }

    public function test_it_sends_error_response_for_operation_exceptions_from_backend_compare(): void
    {
        $compare = new LdapMessageRequest(1, new CompareRequest('cn=foo,dc=bar', Filters::equal('foo', 'bar')));

        $this->mockBackend
            ->method('compare')
            ->willThrowException(new OperationException(
                'No such object: cn=foo,dc=bar',
                ResultCode::NO_SUCH_OBJECT,
            ));

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::callback(function (LdapMessageResponse $msg): bool {
                return $msg->getResponse() instanceof LdapResult
                    && $msg->getResponse()->getResultCode() === ResultCode::NO_SUCH_OBJECT;
            }))
            ->willReturnSelf();

        $this->subject->handleRequest($compare, $this->mockToken);
    }

    public function test_it_sends_error_response_when_no_write_handler_supports_the_operation(): void
    {
        $subject = new ServerDispatchHandler(
            queue: $this->mockQueue,
            backend: $this->mockBackend,
            writeDispatcher: new WriteOperationDispatcher(),
            accessControl: $this->mockAccessControl,
            schema: new Schema(),
        );

        $add = new LdapMessageRequest(1, new AddRequest(Entry::create('cn=foo,dc=bar')));

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::callback(function (LdapMessageResponse $msg): bool {
                return $msg->getResponse() instanceof LdapResult
                    && $msg->getResponse()->getResultCode() === ResultCode::UNWILLING_TO_PERFORM;
            }))
            ->willReturnSelf();

        $subject->handleRequest($add, $this->mockToken);
    }

    public function test_it_sends_error_response_for_unsupported_requests(): void
    {
        $request = new LdapMessageRequest(2, new AbandonRequest(1));

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->willReturnSelf();

        $this->subject->handleRequest($request, $this->mockToken);
    }

    public function test_it_sends_delete_through_the_write_handler(): void
    {
        $delete = new LdapMessageRequest(1, new DeleteRequest('cn=foo,dc=bar'));

        $this->mockWriteHandler
            ->expects(self::once())
            ->method('handle')
            ->with(self::isInstanceOf(WriteRequestInterface::class));

        $this->subject->handleRequest($delete, $this->mockToken);
    }

    public function test_matched_dn_from_exception_is_used_in_write_response(): void
    {
        $matchedDn = new Dn('dc=bar');
        $matchedEntry = Entry::create('dc=bar');
        $delete = new LdapMessageRequest(1, new DeleteRequest('cn=Missing,dc=bar'));

        $this->mockWriteHandler
            ->method('handle')
            ->willThrowException(new OperationException(
                'No such object.',
                ResultCode::NO_SUCH_OBJECT,
                null,
                $matchedDn,
            ));

        $this->mockBackend
            ->method('get')
            ->willReturn($matchedEntry);
        $this->mockAccessControl
            ->method('filterEntry')
            ->willReturn($matchedEntry);

        $captured = null;
        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->willReturnCallback(function (LdapMessageResponse $msg) use (&$captured): LdapMessageResponse {
                $captured = $msg;

                return $msg;
            });

        $this->subject->handleRequest($delete, $this->mockToken);

        $response = $captured?->getResponse();
        self::assertInstanceOf(DeleteResponse::class, $response);
        self::assertSame(
            'dc=bar',
            $response->getDn()->toString(),
        );
    }

    public function test_matched_dn_is_dropped_when_access_control_hides_ancestor(): void
    {
        $matchedDn = new Dn('dc=bar');
        $matchedEntry = Entry::create('dc=bar');
        $delete = new LdapMessageRequest(1, new DeleteRequest('cn=Missing,dc=bar'));

        $this->mockWriteHandler
            ->method('handle')
            ->willThrowException(new OperationException(
                'No such object.',
                ResultCode::NO_SUCH_OBJECT,
                null,
                $matchedDn,
            ));

        $this->mockBackend
            ->method('get')
            ->willReturn($matchedEntry);
        $this->mockAccessControl
            ->method('filterEntry')
            ->willReturn(null);

        $captured = null;
        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->willReturnCallback(function (LdapMessageResponse $msg) use (&$captured): LdapMessageResponse {
                $captured = $msg;

                return $msg;
            });

        $this->subject->handleRequest($delete, $this->mockToken);

        $response = $captured?->getResponse();
        self::assertInstanceOf(DeleteResponse::class, $response);
        self::assertSame(
            '',
            $response->getDn()->toString(),
        );
    }

    public function test_matched_dn_is_dropped_when_backend_returns_no_entry_for_ancestor(): void
    {
        $matchedDn = new Dn('dc=bar');
        $delete = new LdapMessageRequest(1, new DeleteRequest('cn=Missing,dc=bar'));

        $this->mockWriteHandler
            ->method('handle')
            ->willThrowException(new OperationException(
                'No such object.',
                ResultCode::NO_SUCH_OBJECT,
                null,
                $matchedDn,
            ));

        $this->mockBackend
            ->method('get')
            ->willReturn(null);

        $captured = null;
        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->willReturnCallback(function (LdapMessageResponse $msg) use (&$captured): LdapMessageResponse {
                $captured = $msg;

                return $msg;
            });

        $this->subject->handleRequest($delete, $this->mockToken);

        $response = $captured?->getResponse();
        self::assertInstanceOf(DeleteResponse::class, $response);
        self::assertSame(
            '',
            $response->getDn()->toString(),
        );
    }

    public function test_non_critical_unsupported_control_does_not_cause_an_error(): void
    {
        $request = new LdapMessageRequest(
            1,
            new DeleteRequest('cn=foo,dc=bar'),
            new Control('1.2.3.4.5', criticality: false),
        );

        $this->mockWriteHandler
            ->expects(self::once())
            ->method('handle');

        $this->subject->handleRequest(
            $request,
            $this->mockToken,
        );
    }
}
