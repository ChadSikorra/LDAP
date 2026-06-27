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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authenticator;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\Middleware\BindMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcome;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Middleware\CallLog;
use Tests\Support\FreeDSx\Ldap\Middleware\RecordingMiddlewareHandler;

final class BindMiddlewareTest extends TestCase
{
    private ServerAuthorization $authorization;

    private Authenticator&MockObject $authenticator;

    private RecordingMiddlewareHandler $next;

    protected function setUp(): void
    {
        $this->authorization = new ServerAuthorization(new ServerOptions());
        $this->authenticator = $this->createMock(Authenticator::class);
        $this->next = new RecordingMiddlewareHandler(new CallLog());
    }

    public function test_a_non_bind_request_is_delegated(): void
    {
        $this->authenticator
            ->expects(self::never())
            ->method('bind');

        $this->subject()->process(
            new ServerRequestContext(new LdapMessageRequest(
                1,
                new ExtendedRequest(ExtendedRequest::OID_WHOAMI),
            )),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_a_successful_bind_stores_the_token_and_short_circuits(): void
    {
        $token = BindToken::fromDn('cn=user,dc=foo,dc=bar');
        $this->authenticator
            ->method('bind')
            ->willReturn($token);

        $result = $this->subject()->process(
            new ServerRequestContext(new LdapMessageRequest(
                1,
                new SimpleBindRequest('cn=user,dc=foo,dc=bar', 'secret'),
            )),
            $this->next,
        );

        self::assertSame(
            $token,
            $this->authorization->getToken(),
        );
        self::assertNull(
            $this->next->received,
            'A bind must not be delegated to the rest of the pipeline.',
        );
        self::assertSame(
            OperationOutcome::Succeeded,
            $result->outcome(),
        );
    }

    public function test_an_unsupported_authentication_type_is_rejected(): void
    {
        // Anonymous binds are disabled by default.
        $this->authenticator
            ->expects(self::never())
            ->method('bind');

        try {
            $this->subject()->process(
                new ServerRequestContext(new LdapMessageRequest(
                    1,
                    new AnonBindRequest('foo'),
                )),
                $this->next,
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::AUTH_METHOD_UNSUPPORTED,
                $e->getCode(),
            );
        }
    }

    public function test_a_failed_rebind_resets_an_authenticated_session_to_anonymous(): void
    {
        $this->authorization->setToken(BindToken::fromDn('cn=admin,dc=foo,dc=bar'));
        $this->authenticator
            ->method('bind')
            ->willThrowException(new OperationException(
                'Invalid credentials.',
                ResultCode::INVALID_CREDENTIALS,
            ));

        try {
            $this->subject()->process(
                new ServerRequestContext(new LdapMessageRequest(
                    1,
                    new SimpleBindRequest('cn=user,dc=foo,dc=bar', 'wrong'),
                )),
                $this->next,
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException) {
        }

        self::assertInstanceOf(
            AnonToken::class,
            $this->authorization->getToken(),
            'A failed re-bind must drop the prior identity (RFC 4511 §4.2.1).',
        );
    }

    private function subject(): BindMiddleware
    {
        return new BindMiddleware(
            $this->authorization,
            $this->authenticator,
        );
    }
}
