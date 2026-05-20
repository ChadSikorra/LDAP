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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy\Constraint;

use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\AllowUserChangeConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordChangeRules;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use PHPUnit\Framework\TestCase;

final class AllowUserChangeConstraintTest extends TestCase
{
    private AllowUserChangeConstraint $subject;

    protected function setUp(): void
    {
        $this->subject = new AllowUserChangeConstraint();
    }

    public function test_admin_bypasses_the_check(): void
    {
        $outcome = $this->subject->check(
            $this->attempt(
                isSelf: false,
                allowUserChange: false,
            ),
        );

        self::assertNull($outcome);
    }

    public function test_self_with_unset_rule_passes(): void
    {
        $outcome = $this->subject->check(
            $this->attempt(
                isSelf: true,
                allowUserChange: null,
            ),
        );

        self::assertNull($outcome);
    }

    public function test_self_with_explicit_true_passes(): void
    {
        $outcome = $this->subject->check(
            $this->attempt(
                isSelf: true,
                allowUserChange: true,
            ),
        );

        self::assertNull($outcome);
    }

    public function test_self_with_explicit_false_denies(): void
    {
        $outcome = $this->subject->check(
            $this->attempt(
                isSelf: true,
                allowUserChange: false,
            ),
        );

        self::assertNotNull($outcome);
        self::assertTrue($outcome->denied);
        self::assertSame(
            PwdPolicyError::PASSWORD_MOD_NOT_ALLOWED,
            $outcome->errorCode,
        );
    }

    private function attempt(
        bool $isSelf,
        ?bool $allowUserChange,
    ): PasswordChangeAttempt {
        return new PasswordChangeAttempt(
            newPassword: 'irrelevant',
            oldPassword: null,
            state: new UserPasswordState(),
            policy: new PasswordPolicy(
                change: new PasswordChangeRules(allowUserChange: $allowUserChange),
            ),
            isSelf: $isSelf,
        );
    }
}
