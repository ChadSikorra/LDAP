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
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;

/**
 * Evaluates the worst of the replicated entry state and the replica-local bind state on a read-only replica.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ReplicaBindStrategy implements PasswordPolicyBindStrategyInterface
{
    public function __construct(
        private PasswordPolicyEngine $engine,
        private ReplicaPasswordStateStoreInterface $store,
    ) {}

    /**
     * Deny on the primary's entry decision (validity / idle / lock), otherwise on the replica-local failure lock.
     */
    public function preBindOutcome(PasswordBindAttempt $attempt): PasswordPolicyOutcome
    {
        $entryOutcome = $this->engine->evaluatePreBind(
            $attempt->state,
            $attempt->policy,
        );

        if ($entryOutcome->denied) {
            return $entryOutcome;
        }

        return $this->engine->evaluateLocalLockout(
            $this->localState($attempt),
            $attempt->policy,
        );
    }

    public function failureState(PasswordBindAttempt $attempt): UserPasswordState
    {
        return $this->localState($attempt);
    }

    /**
     * Combine primary expiry/validity with replica-local volatile state so success clears local failures and grace.
     */
    public function successState(PasswordBindAttempt $attempt): UserPasswordState
    {
        $entry = $attempt->state;
        $local = $this->localState($attempt);

        return new UserPasswordState(
            changedAt: $entry->changedAt,
            accountLockedAt: $local->accountLockedAt,
            permanentlyLocked: $local->permanentlyLocked,
            failureTimes: $local->failureTimes,
            graceUseTimes: $local->graceUseTimes,
            mustChange: $entry->mustChange,
            policySubentry: $entry->policySubentry,
            startTime: $entry->startTime,
            endTime: $entry->endTime,
            lastSuccess: $local->lastSuccess,
        );
    }

    private function localState(PasswordBindAttempt $attempt): UserPasswordState
    {
        return $this->store
            ->load($attempt->dn)
            ->toUserPasswordState($attempt->dn);
    }
}
