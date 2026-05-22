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

use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\RecordedOutcome;
use PHPUnit\Framework\TestCase;

final class RecordedOutcomeTest extends TestCase
{
    public function test_carries_both_outcome_and_changes(): void
    {
        $outcome = PasswordPolicyOutcome::allow();
        $changes = OperationalChanges::none();

        $recorded = new RecordedOutcome(
            $outcome,
            $changes,
        );

        self::assertSame(
            $outcome,
            $recorded->outcome,
        );
        self::assertSame(
            $changes,
            $recorded->changes,
        );
    }
}
