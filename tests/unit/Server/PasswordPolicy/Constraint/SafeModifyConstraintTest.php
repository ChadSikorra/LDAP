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
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\SafeModifyConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordChangeRules;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use PHPUnit\Framework\TestCase;

final class SafeModifyConstraintTest extends TestCase
{
    private SafeModifyConstraint $subject;

    protected function setUp(): void
    {
        $this->subject = new SafeModifyConstraint();
    }

    public function test_unset_safe_modify_skips(): void
    {
        self::assertNull(
            $this->subject->check(
                $this->attempt(
                    safeModify: null,
                    oldPassword: null,
                ),
            ),
        );
    }

    public function test_disabled_safe_modify_skips(): void
    {
        self::assertNull(
            $this->subject->check(
                $this->attempt(
                    safeModify: false,
                    oldPassword: null,
                ),
            ),
        );
    }

    public function test_enabled_with_old_password_passes(): void
    {
        self::assertNull(
            $this->subject->check(
                $this->attempt(
                    safeModify: true,
                    oldPassword: 'oldpw',
                ),
            ),
        );
    }

    public function test_enabled_without_old_password_denies(): void
    {
        $outcome = $this->subject->check(
            $this->attempt(
                safeModify: true,
                oldPassword: null,
            ),
        );

        self::assertNotNull($outcome);
        self::assertTrue($outcome->denied);
        self::assertSame(
            PwdPolicyError::MUST_SUPPLY_OLD_PASSWORD,
            $outcome->errorCode,
        );
    }

    public function test_enabled_with_empty_string_denies(): void
    {
        $outcome = $this->subject->check(
            $this->attempt(
                safeModify: true,
                oldPassword: '',
            ),
        );

        self::assertNotNull($outcome);
        self::assertTrue($outcome->denied);
    }

    public function test_non_self_change_skips_safe_modify(): void
    {
        self::assertNull(
            $this->subject->check(
                $this->attempt(
                    safeModify: true,
                    oldPassword: null,
                    isSelf: false,
                ),
            ),
        );
    }

    private function attempt(
        ?bool $safeModify,
        ?string $oldPassword,
        bool $isSelf = true,
    ): PasswordChangeAttempt {
        return new PasswordChangeAttempt(
            newPassword: 'newpw',
            oldPassword: $oldPassword,
            state: new UserPasswordState(),
            policy: new PasswordPolicy(
                change: new PasswordChangeRules(safeModify: $safeModify),
            ),
            isSelf: $isSelf,
        );
    }
}
