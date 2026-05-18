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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Server\PasswordPolicy\OperationalChanges;
use PHPUnit\Framework\TestCase;

final class OperationalChangesTest extends TestCase
{
    public function test_none_is_empty(): void
    {
        $changes = OperationalChanges::none();

        self::assertTrue($changes->isEmpty());
        self::assertSame(
            [],
            $changes->changes,
        );
    }

    public function test_of_carries_changes(): void
    {
        $a = Change::replace(new Attribute('pwdChangedTime', '20250101000000Z'));
        $b = Change::reset(new Attribute('pwdFailureTime'));

        $changes = OperationalChanges::of(
            $a,
            $b,
        );

        self::assertFalse($changes->isEmpty());
        self::assertSame(
            [$a, $b],
            $changes->changes,
        );
    }
}
