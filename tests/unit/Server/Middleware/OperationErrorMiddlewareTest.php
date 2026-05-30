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

namespace Tests\Unit\FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Middleware\OperationErrorMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcome;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Middleware\StubMiddlewareHandler;
use Tests\Support\FreeDSx\Ldap\Middleware\ThrowingMiddlewareHandler;

final class OperationErrorMiddlewareTest extends TestCase
{
    private ServerQueue&MockObject $mockQueue;

    private LdapBackendInterface&MockObject $mockBackend;

    private AccessControlInterface&MockObject $mockAccessControl;

    private TokenInterface&MockObject $mockToken;

    private OperationErrorMiddleware $subject;

    private ?LdapMessageResponse $sent = null;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockBackend = $this->createMock(LdapBackendInterface::class);
        $this->mockAccessControl = $this->createMock(AccessControlInterface::class);
        $this->mockToken = $this->createMock(TokenInterface::class);

        $this->mockQueue
            ->method('sendMessage')
            ->willReturnCallback(function (LdapMessageResponse $response): ServerQueue {
                $this->sent = $response;

                return $this->mockQueue;
            });

        $this->subject = new OperationErrorMiddleware(
            $this->mockQueue,
            $this->mockBackend,
            $this->mockAccessControl,
        );
    }

    public function test_it_passes_a_successful_result_through_without_sending(): void
    {
        $this->mockQueue
            ->expects(self::never())
            ->method('sendMessage');

        $result = OperationOutcomeResult::succeeded();

        self::assertSame(
            $result,
            $this->subject->process(
                $this->contextFor(new DeleteRequest('cn=foo,dc=bar')),
                new StubMiddlewareHandler($result),
            ),
        );
    }

    public function test_it_renders_the_response_for_a_thrown_exception_and_does_not_rethrow(): void
    {
        $result = $this->subject->process(
            $this->contextFor(new DeleteRequest('cn=foo,dc=bar')),
            new ThrowingMiddlewareHandler(new OperationException(
                'Unwilling.',
                ResultCode::UNWILLING_TO_PERFORM,
            )),
        );

        self::assertSame(
            OperationOutcome::Failed,
            $result->outcome(),
        );

        $response = $this->sent?->getResponse();
        self::assertInstanceOf(DeleteResponse::class, $response);
        self::assertSame(
            ResultCode::UNWILLING_TO_PERFORM,
            $response->getResultCode(),
        );
    }

    public function test_it_keeps_a_matched_dn_the_token_may_see(): void
    {
        $this->mockBackend
            ->method('get')
            ->willReturn(Entry::create('dc=bar'));
        $this->mockAccessControl
            ->method('filterEntry')
            ->willReturn(Entry::create('dc=bar'));

        $this->subject->process(
            $this->contextFor(new DeleteRequest('cn=missing,dc=bar')),
            new ThrowingMiddlewareHandler($this->noSuchObject(new Dn('dc=bar'))),
        );

        $response = $this->sent?->getResponse();
        self::assertInstanceOf(DeleteResponse::class, $response);
        self::assertSame(
            'dc=bar',
            $response->getDn()->toString(),
        );
    }

    public function test_it_drops_a_matched_dn_the_access_control_hides(): void
    {
        $this->mockBackend
            ->method('get')
            ->willReturn(Entry::create('dc=bar'));
        $this->mockAccessControl
            ->method('filterEntry')
            ->willReturn(null);

        $this->subject->process(
            $this->contextFor(new DeleteRequest('cn=missing,dc=bar')),
            new ThrowingMiddlewareHandler($this->noSuchObject(new Dn('dc=bar'))),
        );

        $response = $this->sent?->getResponse();
        self::assertInstanceOf(DeleteResponse::class, $response);
        self::assertSame(
            '',
            $response->getDn()->toString(),
        );
    }

    public function test_it_drops_a_matched_dn_when_the_backend_has_no_ancestor(): void
    {
        $this->mockBackend
            ->method('get')
            ->willReturn(null);

        $this->subject->process(
            $this->contextFor(new DeleteRequest('cn=missing,dc=bar')),
            new ThrowingMiddlewareHandler($this->noSuchObject(new Dn('dc=bar'))),
        );

        $response = $this->sent?->getResponse();
        self::assertInstanceOf(DeleteResponse::class, $response);
        self::assertSame(
            '',
            $response->getDn()->toString(),
        );
    }

    private function noSuchObject(Dn $matchedDn): OperationException
    {
        return new OperationException(
            'No such object.',
            ResultCode::NO_SUCH_OBJECT,
            null,
            $matchedDn,
        );
    }

    private function contextFor(RequestInterface $request): ServerRequestContext
    {
        return new ServerRequestContext(
            new LdapMessageRequest(1, $request),
            $this->mockToken,
        );
    }
}
