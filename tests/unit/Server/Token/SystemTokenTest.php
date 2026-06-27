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

namespace Tests\Unit\FreeDSx\Ldap\Server\Token;

use FreeDSx\Ldap\Server\Token\SystemToken;
use PHPUnit\Framework\TestCase;

final class SystemTokenTest extends TestCase
{
    public function test_it_reports_the_system_identity(): void
    {
        $token = new SystemToken();

        self::assertSame(
            'cn=system',
            $token->getUsername(),
        );
        self::assertSame(
            SystemToken::IDENTITY,
            $token->getUsername(),
        );
    }

    public function test_its_authz_id_is_the_system_identity(): void
    {
        self::assertSame(
            'cn=system',
            (new SystemToken())->getAuthzId()->getValue(),
        );
    }

    public function test_it_defaults_to_ldap_v3(): void
    {
        self::assertSame(
            3,
            (new SystemToken())->getVersion(),
        );
    }

    public function test_each_instance_has_a_unique_id(): void
    {
        self::assertNotSame(
            (new SystemToken())->getId(),
            (new SystemToken())->getId(),
        );
    }
}
