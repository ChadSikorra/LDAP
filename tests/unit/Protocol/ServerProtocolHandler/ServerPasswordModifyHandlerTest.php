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
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerPasswordModifyHandler;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerPasswordModifyHandlerTest extends TestCase
{
    private ServerQueue&MockObject $mockQueue;

    private LdapBackendInterface&MockObject $mockBackend;

    private AccessControlInterface&MockObject $mockAcl;

    private BindNameResolverInterface&MockObject $mockResolver;

    private WriteHandlerInterface&MockObject $mockWriteHandler;

    private ServerPasswordModifyHandler $subject;

    private Entry $userEntry;

    private BindToken $userToken;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockBackend = $this->createMock(LdapBackendInterface::class);
        $this->mockAcl = $this->createMock(AccessControlInterface::class);
        $this->mockResolver = $this->createMock(BindNameResolverInterface::class);
        $this->mockWriteHandler = $this->createMock(WriteHandlerInterface::class);

        $this->mockQueue->method('sendMessage')->willReturnSelf();
        $this->mockWriteHandler->method('supports')->willReturn(true);

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
            backend: $this->mockBackend,
            writeDispatcher: new WriteOperationDispatcher($this->mockWriteHandler),
            accessControl: $this->mockAcl,
            identityResolver: $this->mockResolver,
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

        $this->subject->handleRequest(
            new LdapMessageRequest(
                1,
                new PasswordModifyRequest(null, '12345', 'newpass'),
            ),
            $this->userToken,
        );
    }

    public function test_admin_reset_uses_identity_resolver(): void
    {
        $this->mockResolver
            ->expects(self::once())
            ->method('resolve')
            ->with('cn=user,dc=foo,dc=bar', $this->mockBackend)
            ->willReturn($this->userEntry);

        $this->subject->handleRequest(
            new LdapMessageRequest(
                1,
                new PasswordModifyRequest('cn=user,dc=foo,dc=bar', null, 'reset123'),
            ),
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
                'adminpass',
            ),
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

    public function test_non_existent_target_returns_no_such_object(): void
    {
        $this->mockBackend
            ->method('get')
            ->willReturn(null);

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::callback(
                fn(LdapMessageResponse $r)
                => method_exists($r->getResponse(), 'getResultCode')
                && $r->getResponse()->getResultCode() === ResultCode::NO_SUCH_OBJECT,
            ));

        $this->subject->handleRequest(
            new LdapMessageRequest(
                1,
                new PasswordModifyRequest(null, null, 'newpass'),
            ),
            $this->userToken,
        );
    }

    public function test_old_password_matches_any_stored_value(): void
    {
        $this->mockBackend
            ->method('get')
            ->willReturn(new Entry(
                new Dn('cn=user,dc=foo,dc=bar'),
                new Attribute('userPassword', 'first', '12345'),
            ));

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::callback(
                fn(LdapMessageResponse $r)
                => $r->getResponse() instanceof PasswordModifyResponse
                && $r->getResponse()->getGeneratedPassword() === null,
            ));

        $this->subject->handleRequest(
            new LdapMessageRequest(
                1,
                new PasswordModifyRequest(null, '12345', 'newpass'),
            ),
            $this->userToken,
        );
    }

    public function test_wrong_old_password_returns_invalid_credentials(): void
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

        $this->subject->handleRequest(
            new LdapMessageRequest(
                1,
                new PasswordModifyRequest(null, 'wrongpass', 'newpass'),
            ),
            $this->userToken,
        );
    }

    public function test_acl_denial_returns_insufficient_access_rights(): void
    {
        $this->mockBackend
            ->method('get')
            ->willReturn($this->userEntry);

        $this->mockAcl
            ->method('authorizeOperation')
            ->willThrowException(new OperationException(
                'Access denied.',
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            ));

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::callback(
                fn(LdapMessageResponse $r)
                => method_exists($r->getResponse(), 'getResultCode')
                && $r->getResponse()->getResultCode() === ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            ));

        $this->subject->handleRequest(
            new LdapMessageRequest(
                1,
                new PasswordModifyRequest(null, null, 'newpass'),
            ),
            $this->userToken,
        );
    }

    public function test_resolver_returning_null_returns_no_such_object(): void
    {
        $this->mockResolver
            ->method('resolve')
            ->willReturn(null);

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::callback(
                fn(LdapMessageResponse $r)
                => method_exists($r->getResponse(), 'getResultCode')
                && $r->getResponse()->getResultCode() === ResultCode::NO_SUCH_OBJECT,
            ));

        $this->subject->handleRequest(
            new LdapMessageRequest(
                1,
                new PasswordModifyRequest('cn=ghost,dc=foo,dc=bar', null, 'newpass'),
            ),
            $this->userToken,
        );
    }
}
