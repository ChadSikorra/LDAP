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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerPasswordModifyHandler;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Operation\OperationOutcome;
use FreeDSx\Ldap\Server\Operation\PasswordModifyOperationResult;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyService;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyTargetResolver;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * Covers the transport seam: decoding, response encoding, and error mapping. The use case itself is exercised by
 * {@see \Tests\Unit\FreeDSx\Ldap\Server\PasswordModify\PasswordModifyServiceTest}.
 */
final class ServerPasswordModifyHandlerTest extends TestCase
{
    private ServerQueue&MockObject $mockQueue;

    private LdapBackendInterface&MockObject $mockBackend;

    private ServerPasswordModifyHandler $subject;

    private Entry $userEntry;

    private BindToken $userToken;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockBackend = $this->createMock(LdapBackendInterface::class);
        $mockWriteHandler = $this->createMock(WriteHandlerInterface::class);

        $this->mockQueue->method('sendMessage')->willReturnSelf();
        $mockWriteHandler->method('supports')->willReturn(true);

        $this->userEntry = new Entry(
            new Dn('cn=user,dc=foo,dc=bar'),
            new Attribute('userPassword', '12345'),
        );
        $this->userToken = BindToken::fromDn(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        $this->subject = new ServerPasswordModifyHandler(
            queue: $this->mockQueue,
            service: new PasswordModifyService(
                targetResolver: new PasswordModifyTargetResolver(
                    $this->mockBackend,
                    $this->createMock(BindNameResolverInterface::class),
                ),
                accessControl: $this->createMock(AccessControlInterface::class),
                writeDispatcher: new WriteOperationDispatcher($mockWriteHandler),
                hashService: new PasswordHashService(hashCost: 4),
            ),
        );
    }

    public function test_self_service_change_sends_success_response(): void
    {
        $this->mockBackend
            ->method('get')
            ->willReturn($this->userEntry);

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::callback(
                fn(LdapMessageResponse $r)
                => $r->getResponse() instanceof PasswordModifyResponse
                && $r->getResponse()->getGeneratedPassword() === null,
            ));

        $result = $this->subject->handleRequest(
            new LdapMessageRequest(
                1,
                new PasswordModifyRequest(null, '12345', 'newpass'),
            ),
            $this->userToken,
        );

        self::assertInstanceOf(PasswordModifyOperationResult::class, $result);
        self::assertSame(
            OperationOutcome::Succeeded,
            $result->outcome(),
        );
    }

    public function test_server_generated_password_is_returned_in_response(): void
    {
        $this->mockBackend
            ->method('get')
            ->willReturn($this->userEntry);

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::callback(
                fn(LdapMessageResponse $r)
                => $r->getResponse() instanceof PasswordModifyResponse
                && strlen((string) $r->getResponse()->getGeneratedPassword()) === 16,
            ));

        $this->subject->handleRequest(
            new LdapMessageRequest(
                1,
                new PasswordModifyRequest(null, '12345', null),
            ),
            $this->userToken,
        );
    }

    public function test_anonymous_token_is_rejected_with_unwilling_to_perform(): void
    {
        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::callback(
                fn(LdapMessageResponse $r)
                => method_exists($r->getResponse(), 'getResultCode')
                && $r->getResponse()->getResultCode() === ResultCode::UNWILLING_TO_PERFORM,
            ));

        $this->subject->handleRequest(
            new LdapMessageRequest(1, new PasswordModifyRequest()),
            new AnonToken(),
        );
    }

    public function test_an_operation_error_is_sent_as_a_standard_response(): void
    {
        $this->mockBackend
            ->method('get')
            ->willReturn($this->userEntry);

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::callback(
                fn(LdapMessageResponse $r)
                => method_exists($r->getResponse(), 'getResultCode')
                && $r->getResponse()->getResultCode() === ResultCode::INVALID_CREDENTIALS,
            ));

        $result = $this->subject->handleRequest(
            new LdapMessageRequest(
                1,
                new PasswordModifyRequest(null, 'wrongpass', 'newpass'),
            ),
            $this->userToken,
        );

        self::assertInstanceOf(PasswordModifyOperationResult::class, $result);
        self::assertSame(
            OperationOutcome::Failed,
            $result->outcome(),
        );
    }
}
