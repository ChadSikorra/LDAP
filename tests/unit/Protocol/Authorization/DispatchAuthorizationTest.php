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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Authorization;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\Authorization\DispatchAuthorization;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;

final class DispatchAuthorizationTest extends TestCase
{
    public function test_proceed_carries_the_effective_token(): void
    {
        $token = new BindToken(
            'cn=alice,dc=example,dc=com',
            'secret',
            new Dn('cn=alice,dc=example,dc=com'),
        );

        $authorization = DispatchAuthorization::proceed($token);

        self::assertFalse($authorization->requiresAuthentication());
        self::assertFalse($authorization->requiresPasswordChange());
        self::assertSame(
            $token,
            $authorization->token(),
        );
    }

    public function test_authentication_required_has_no_token(): void
    {
        $authorization = DispatchAuthorization::authenticationRequired();

        self::assertTrue($authorization->requiresAuthentication());
        self::assertFalse($authorization->requiresPasswordChange());

        $this->expectException(RuntimeException::class);
        $authorization->token();
    }

    public function test_password_change_required_has_no_token(): void
    {
        $authorization = DispatchAuthorization::passwordChangeRequired();

        self::assertTrue($authorization->requiresPasswordChange());
        self::assertFalse($authorization->requiresAuthentication());

        $this->expectException(RuntimeException::class);
        $authorization->token();
    }
}
