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

/**
 * Requires the client to supply the existing password when pwdSafeModify is enabled.
 */
final readonly class SafeModifyConstraint implements PasswordChangeConstraint
{
    public function check(PasswordChangeAttempt $attempt): ?PasswordPolicyOutcome
    {
        if ($attempt->policy->change->safeModify !== true || ($attempt->oldPassword ?? '') !== '') {
            return null;
        }

        return PasswordPolicyOutcome::deny(
            PwdPolicyError::MUST_SUPPLY_OLD_PASSWORD,
            ResultCode::CONSTRAINT_VIOLATION,
            'The existing password must be supplied.',
        );
    }
}
