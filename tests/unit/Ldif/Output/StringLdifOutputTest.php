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

namespace Tests\Unit\FreeDSx\Ldap\Ldif\Output;

use FreeDSx\Ldap\Ldif\Output\StringLdifOutput;
use PHPUnit\Framework\TestCase;

final class StringLdifOutputTest extends TestCase
{
    public function test_it_concatenates_chunks_in_order(): void
    {
        $output = new StringLdifOutput();

        $output->write([
            "version: 1\n\n",
            "dn: cn=a,dc=x\n",
            "cn: a\n",
        ]);

        self::assertSame(
            "version: 1\n\ndn: cn=a,dc=x\ncn: a\n",
            $output->getLdif(),
        );
    }

    public function test_stringable_returns_the_same_value_as_getLdif(): void
    {
        $output = new StringLdifOutput();
        $output->write(["dn: cn=a,dc=x\n"]);

        self::assertSame(
            $output->getLdif(),
            (string) $output,
        );
    }

    public function test_repeated_writes_accumulate(): void
    {
        $output = new StringLdifOutput();
        $output->write(["first\n"]);
        $output->write(["second\n"]);

        self::assertSame(
            "first\nsecond\n",
            $output->getLdif(),
        );
    }

    public function test_empty_writes_produce_an_empty_string(): void
    {
        $output = new StringLdifOutput();
        $output->write([]);

        self::assertSame(
            '',
            $output->getLdif(),
        );
    }
}
