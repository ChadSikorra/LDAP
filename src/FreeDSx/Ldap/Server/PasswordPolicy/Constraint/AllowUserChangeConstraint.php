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
 * Denies a self-service change when pwdAllowUserChange is explicitly false.
 */
final readonly class AllowUserChangeConstraint implements PasswordChangeConstraint
{
    public function check(PasswordChangeAttempt $attempt): ?PasswordPolicyOutcome
    {
        if (!$attempt->isSelf || $attempt->policy->change->allowUserChange !== false) {
            return null;
        }

        return PasswordPolicyOutcome::deny(
            PwdPolicyError::PASSWORD_MOD_NOT_ALLOWED,
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            'Self-service password change is not permitted by policy.',
        );
    }
}
