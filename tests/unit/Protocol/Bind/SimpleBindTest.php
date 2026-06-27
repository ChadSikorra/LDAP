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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Bind;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Bind\SimpleBind;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class SimpleBindTest extends TestCase
{
    private SimpleBind $subject;

    private PasswordAuthenticatableInterface&MockObject $mockAuthenticator;

    private ServerQueue&MockObject $mockQueue;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockAuthenticator = $this->createMock(PasswordAuthenticatableInterface::class);

        $this->subject = new SimpleBind(
            $this->mockQueue,
            $this->mockAuthenticator,
        );
    }

    public function test_it_should_return_a_token_on_success(): void
    {
        $expectedToken = BindToken::fromSasl(
            'foo@bar',
            new Dn('cn=foo,dc=bar'),
        );

        $this->mockAuthenticator
            ->expects(self::once())
            ->method('authenticate')
            ->with('foo@bar', 'bar')
            ->willReturn($expectedToken);

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::equalTo(
                new LdapMessageResponse(
                    1,
                    new BindResponse(new LdapResult(0)),
                ),
            ));

        $bind = new LdapMessageRequest(
            1,
            new SimpleBindRequest(
                'foo@bar',
                'bar',
            ),
        );

        $token = $this->subject->bind($bind);

        self::assertSame(
            $expectedToken,
            $token,
        );
    }

    public function test_it_should_propagate_exception_on_invalid_credentials(): void
    {
        $this->mockAuthenticator
            ->expects(self::once())
            ->method('authenticate')
            ->with('foo@bar', 'bar')
            ->willThrowException(new OperationException(
                'Invalid credentials.',
                ResultCode::INVALID_CREDENTIALS,
            ));

        $this->mockQueue
            ->expects(self::never())
            ->method('sendMessage');

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $this->subject->bind(new LdapMessageRequest(
            1,
            new SimpleBindRequest('foo@bar', 'bar'),
        ));
    }

    public function test_it_should_validate_the_version(): void
    {
        $this->mockQueue
            ->expects(self::never())
            ->method('sendMessage');

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        $this->subject->bind(
            new LdapMessageRequest(
                1,
                new SimpleBindRequest(
                    username: 'foo@bar',
                    password: 'bar',
                    version: 5,
                ),
            ),
        );
    }

    public function test_it_should_only_support_simple_binds(): void
    {
        self::assertFalse($this->subject->supports(new LdapMessageRequest(
            1,
            new AnonBindRequest(),
        )));
        self::assertTrue($this->subject->supports(new LdapMessageRequest(
            1,
            new SimpleBindRequest(
                'foo',
                'bar',
            ),
        )));
    }
}
