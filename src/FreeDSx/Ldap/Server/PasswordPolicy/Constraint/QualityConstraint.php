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
}
