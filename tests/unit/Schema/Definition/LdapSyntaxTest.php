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

namespace Tests\Unit\FreeDSx\Ldap\Schema\Definition;

use FreeDSx\Ldap\Schema\Definition\LdapSyntax;
use PHPUnit\Framework\TestCase;

final class LdapSyntaxTest extends TestCase
{
    public function test_description_string_with_desc(): void
    {
        $syntax = new LdapSyntax(
            oid: '1.3.6.1.4.1.1466.115.121.1.15',
            desc: 'Directory String',
        );

        self::assertSame(
            "( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )",
            $syntax->toDescriptionString(),
        );
    }

    public function test_description_string_without_desc(): void
    {
        $syntax = new LdapSyntax(oid: '1.3.6.1.4.1.1466.115.121.1.40');

        self::assertSame(
            '( 1.3.6.1.4.1.1466.115.121.1.40 )',
            $syntax->toDescriptionString(),
        );
    }

    public function test_description_string_with_extensions(): void
    {
        $syntax = new LdapSyntax(
            oid: '1.3.6.1.4.1.1466.115.121.1.15',
            desc: 'Directory String',
            extensions: ['X-ORIGIN' => ['RFC 4517']],
        );

        self::assertSame(
            "( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' X-ORIGIN 'RFC 4517' )",
            $syntax->toDescriptionString(),
        );
    }
}
