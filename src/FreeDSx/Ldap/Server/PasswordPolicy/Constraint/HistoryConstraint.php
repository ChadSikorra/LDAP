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
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashVerifier;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;

/**
 * Denies a change whose new value matches any retained pwdHistory entry.
 */
final readonly class HistoryConstraint implements PasswordChangeConstraint
{
    public function __construct(private PasswordHashVerifier $hashVerifier) {}

    /**
     * Comparison goes through {@see PasswordHashVerifier}; entries stored under a no-longer-supported
     * scheme silently fail to match and effectively drop out of the history set (draft-behera-10 §5.3.7).
     */
    public function check(PasswordChangeAttempt $attempt): ?PasswordPolicyOutcome
    {
        $depth = $attempt->policy->quality->inHistory;
        if ($depth === null || $depth === 0 || $attempt->state->history === []) {
            return null;
        }

        foreach ($attempt->state->history as $entry) {
            if ($this->hashVerifier->verify($attempt->newPassword, $entry->data)) {
                return PasswordPolicyOutcome::deny(
                    PwdPolicyError::PASSWORD_IN_HISTORY,
                    ResultCode::CONSTRAINT_VIOLATION,
                    'Password matches a recently used password.',
                );
            }
        }

        return null;
    }
}
