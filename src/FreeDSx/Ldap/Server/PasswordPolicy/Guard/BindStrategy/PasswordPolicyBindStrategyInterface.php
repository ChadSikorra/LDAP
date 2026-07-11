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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Guard\BindStrategy;

use FreeDSx\Ldap\Server\PasswordPolicy\Attempt\PasswordBindAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;

/**
 * Supplies the password-policy state each bind operation is evaluated and recorded against.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PasswordPolicyBindStrategyInterface
{
    /**
     * The pre-bind lockout decision (worst-outcome across every state that governs the bind).
     */
    public function preBindOutcome(PasswordBindAttempt $attempt): PasswordPolicyOutcome;

    /**
     * The state a failed bind is counted and recorded against.
     */
    public function failureState(PasswordBindAttempt $attempt): UserPasswordState;

    /**
     * The state a successful bind is evaluated and cleared against.
     */
    public function successState(PasswordBindAttempt $attempt): UserPasswordState;
}
