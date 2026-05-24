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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Constraint;

use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\PasswordQualityCheckerInterface;

/**
 * Delegates to the configured {@see PasswordQualityCheckerInterface}; maps any returned code into a deny outcome.
 */
final readonly class QualityConstraint implements PasswordChangeConstraint
{
    public function __construct(private PasswordQualityCheckerInterface $checker) {}

    public function check(PasswordChangeAttempt $attempt): ?PasswordPolicyOutcome
    {
        if (!$attempt->passwordIsCleartext) {
            return $this->forUninspectablePassword($attempt->policy->quality->checkQuality);
        }

        $errorCode = $this->checker->check(
            $attempt->newPassword,
            $attempt->policy->quality,
        );
        if ($errorCode === null) {
            return null;
        }

        return PasswordPolicyOutcome::deny(
            $errorCode,
            ResultCode::CONSTRAINT_VIOLATION,
            'Password does not meet quality requirements.',
        );
    }

    /**
     * pwdCheckQuality = 2 forbids accepting a password whose quality cannot be checked (draft-behera-10 §5.2.5).
     */
    private function forUninspectablePassword(?int $checkQuality): ?PasswordPolicyOutcome
    {
        if ($checkQuality !== 2) {
            return null;
        }

        return PasswordPolicyOutcome::deny(
            PwdPolicyError::INSUFFICIENT_PASSWORD_QUALITY,
            ResultCode::CONSTRAINT_VIOLATION,
            'Password quality cannot be verified for a pre-hashed value.',
        );
    }
}
