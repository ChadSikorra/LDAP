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
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\QualityConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\PasswordQualityCheckerInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use PHPUnit\Framework\TestCase;

final class QualityConstraintTest extends TestCase
{
    public function test_checker_returning_null_allows(): void
    {
        $checker = $this->createMock(PasswordQualityCheckerInterface::class);
        $checker
            ->method('check')
            ->willReturn(null);

        $constraint = new QualityConstraint($checker);

        self::assertNull($constraint->check($this->attempt()));
    }

    public function test_checker_returning_code_denies_with_same_code(): void
    {
        $checker = $this->createMock(PasswordQualityCheckerInterface::class);
        $checker
            ->method('check')
            ->willReturn(PwdPolicyError::PASSWORD_TOO_SHORT);

        $constraint = new QualityConstraint($checker);

        $outcome = $constraint->check($this->attempt());

        self::assertNotNull($outcome);
        self::assertTrue($outcome->denied);
        self::assertSame(
            PwdPolicyError::PASSWORD_TOO_SHORT,
            $outcome->errorCode,
        );
    }

    public function test_quality_code_propagates(): void
    {
        $checker = $this->createMock(PasswordQualityCheckerInterface::class);
        $checker
            ->method('check')
            ->willReturn(PwdPolicyError::INSUFFICIENT_PASSWORD_QUALITY);

        $constraint = new QualityConstraint($checker);

        $outcome = $constraint->check($this->attempt());

        self::assertNotNull($outcome);
        self::assertSame(
            PwdPolicyError::INSUFFICIENT_PASSWORD_QUALITY,
            $outcome->errorCode,
        );
    }

    public function test_prehashed_value_is_not_passed_to_the_checker(): void
    {
        $checker = $this->createMock(PasswordQualityCheckerInterface::class);
        $checker
            ->expects(self::never())
            ->method('check');

        $constraint = new QualityConstraint($checker);

        self::assertNull($constraint->check($this->attempt(
            checkQuality: 1,
            passwordIsCleartext: false,
        )));
    }

    public function test_prehashed_value_denied_when_check_quality_is_strict(): void
    {
        $checker = $this->createMock(PasswordQualityCheckerInterface::class);
        $checker
            ->expects(self::never())
            ->method('check');

        $constraint = new QualityConstraint($checker);

        $outcome = $constraint->check($this->attempt(
            checkQuality: 2,
            passwordIsCleartext: false,
        ));

        self::assertNotNull($outcome);
        self::assertTrue($outcome->denied);
        self::assertSame(
            PwdPolicyError::INSUFFICIENT_PASSWORD_QUALITY,
            $outcome->errorCode,
        );
    }

    public function test_cleartext_value_is_still_checked(): void
    {
        $checker = $this->createMock(PasswordQualityCheckerInterface::class);
        $checker
            ->expects(self::once())
            ->method('check')
            ->willReturn(PwdPolicyError::PASSWORD_TOO_SHORT);

        $constraint = new QualityConstraint($checker);

        $outcome = $constraint->check($this->attempt(
            checkQuality: 2,
            passwordIsCleartext: true,
        ));

        self::assertNotNull($outcome);
        self::assertSame(
            PwdPolicyError::PASSWORD_TOO_SHORT,
            $outcome->errorCode,
        );
    }

    /**
     * @param int<0, max>|null $checkQuality
     */
    private function attempt(
        ?int $checkQuality = null,
        bool $passwordIsCleartext = true,
    ): PasswordChangeAttempt {
        return new PasswordChangeAttempt(
            newPassword: 'newpw',
            oldPassword: null,
            state: new UserPasswordState(),
            policy: new PasswordPolicy(quality: new PasswordQualityRules(checkQuality: $checkQuality)),
            isSelf: true,
            passwordIsCleartext: $passwordIsCleartext,
        );
    }
}
