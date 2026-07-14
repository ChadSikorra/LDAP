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
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\RecordedOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;

/**
 * Evaluates and atomically records each bind against the password-policy state that governs it.
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
     * Atomically read the subject's current state, run $decide against it, persist the changes it yields, and return
     * the decision, all under an exclusive lock so concurrent binds cannot lose an update.
     *
     * @param callable(UserPasswordState): RecordedOutcome $decide
     */
    public function record(
        PasswordBindAttempt $attempt,
        callable $decide,
    ): RecordedOutcome;
}
