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

use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyOutcome;

/**
 * One gate in the password-change pipeline; returns a deny outcome on violation or null when satisfied.
 */
interface PasswordChangeConstraint
{
    public function check(PasswordChangeAttempt $attempt): ?PasswordPolicyOutcome;
}
