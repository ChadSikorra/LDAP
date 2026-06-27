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

namespace Tests\Unit\FreeDSx\Ldap\Server\Middleware\Pipeline;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;

final class ServerRequestContextTest extends TestCase
{
    private ServerRequestContext $subject;

    protected function setUp(): void
    {
        $this->subject = new ServerRequestContext(new LdapMessageRequest(
            1,
            new ExtendedRequest(ExtendedRequest::OID_WHOAMI),
        ));
    }

    public function test_the_token_is_null_until_resolved(): void
    {
        self::assertNull($this->subject->token());
    }

    public function test_token_or_fail_throws_when_no_token_is_resolved(): void
    {
        $this->expectException(RuntimeException::class);

        $this->subject->tokenOrFail();
    }

    public function test_with_token_returns_a_new_context_carrying_the_token(): void
    {
        $token = BindToken::fromDn('cn=user,dc=foo,dc=bar');

        $withToken = $this->subject->withToken($token);

        self::assertNotSame(
            $this->subject,
            $withToken,
        );
        self::assertNull($this->subject->token());
        self::assertSame(
            $token,
            $withToken->token(),
        );
        self::assertSame(
            $token,
            $withToken->tokenOrFail(),
        );
        self::assertSame(
            $this->subject->message,
            $withToken->message,
        );
    }
}
