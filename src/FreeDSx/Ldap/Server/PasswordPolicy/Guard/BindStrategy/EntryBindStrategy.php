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
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;

/**
 * Evaluates every bind operation against the authoritative entry state (the primary / writable server).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class EntryBindStrategy implements PasswordPolicyBindStrategyInterface
{
    public function __construct(private PasswordPolicyEngine $engine) {}

    public function preBindOutcome(PasswordBindAttempt $attempt): PasswordPolicyOutcome
    {
        return $this->engine->evaluatePreBind(
            $attempt->state,
            $attempt->policy,
        );
    }

    public function failureState(PasswordBindAttempt $attempt): UserPasswordState
    {
        return $attempt->state;
    }

    public function successState(PasswordBindAttempt $attempt): UserPasswordState
    {
        return $attempt->state;
    }
}
