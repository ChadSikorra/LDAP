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

namespace FreeDSx\Ldap\Server\PasswordPolicy;

use DateTimeImmutable;
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\Clock\ClockInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\RecordedOutcome;
use SensitiveParameter;

/**
 * Core decision / tracking engine for draft-behera-10 password policy.
 */
final readonly class PasswordPolicyEngine
{
    public function __construct(
        private ClockInterface $clock,
        private PasswordChangeConstraintChain $changeConstraints,
    ) {}

    /**
     * Lockout check applied before the inner authenticator verifies credentials.
     */
    public function evaluatePreBind(
        UserPasswordState $state,
        PasswordPolicy $policy,
    ): PasswordPolicyOutcome {
        if (!$state->isLocked()) {
            return PasswordPolicyOutcome::allow();
        }

        if ($state->permanentlyLocked) {
            return self::denyLocked();
        }

        $duration = $policy->lockout->duration;
        if ($duration === null || $duration === 0) {
            return self::denyLocked();
        }

        if ($this->secondsSinceLock($state) < $duration) {
            return self::denyLocked();
        }

        return PasswordPolicyOutcome::allow();
    }

    /**
     * Record a failed bind: append the current time to pwdFailureTime, and trip the lockout if the retained failure count meets pwdMaxFailure.
     *
     * Note: pwdFailureTime accumulates regardless of pwdLockout. Only the lock transition requires pwdLockout=TRUE (draft-behera-10 §5.2.9, §5.3.2).
     */
    public function recordBindFailure(
        UserPasswordState $state,
        PasswordPolicy $policy,
    ): RecordedOutcome {
        $now = $this->clock->now();
        $retained = $this->trimFailuresToInterval(
            $state->failureTimes,
            $policy,
        );
        $retained[] = $now;

        $changes = [Change::replace(
            PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
            ...self::formatTimes($retained),
        )];

        $outcome = PasswordPolicyOutcome::allow();

        if ($this->shouldTripLockout($state, $policy, $retained)) {
            $changes[] = Change::replace(
                PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
                GeneralizedTime::format($now),
            );
            $outcome = self::denyLocked();
        }

        return new RecordedOutcome(
            $outcome,
            OperationalChanges::of(...$changes),
        );
    }

    /**
     * @param list<DateTimeImmutable> $failures
     * @return list<DateTimeImmutable>
     */
    private function trimFailuresToInterval(
        array $failures,
        PasswordPolicy $policy,
    ): array {
        $interval = $policy->lockout->failureCountInterval;
        if ($interval === null || $interval === 0) {
            return $failures;
        }

        $nowTs = $this->clock->now()->getTimestamp();

        return array_values(array_filter(
            $failures,
            static fn(DateTimeImmutable $t): bool => ($nowTs - $t->getTimestamp()) < $interval,
        ));
    }

    /**
     * @param list<DateTimeImmutable> $retained
     */
    private function shouldTripLockout(
        UserPasswordState $state,
        PasswordPolicy $policy,
        array $retained,
    ): bool {
        return match (true) {
            $policy->lockout->enabled !== true,
            $policy->lockout->maxFailure === null,
            $policy->lockout->maxFailure === 0,
            $state->isLocked() => false,
            default => count($retained) >= $policy->lockout->maxFailure,
        };
    }

    /**
     * May deny if the password is expired and no grace remains; otherwise clears failures / lockout and surfaces any
     * warning (expiration, grace, reset).
     */
    public function recordBindSuccess(
        UserPasswordState $state,
        PasswordPolicy $policy,
    ): RecordedOutcome {
        $now = $this->clock->now();
        $secondsRemaining = $this->secondsUntilExpiration(
            $state,
            $policy,
        );
        $isExpired = $secondsRemaining !== null && $secondsRemaining <= 0;

        if ($isExpired && $this->graceRemaining($state, $policy) === 0) {
            return new RecordedOutcome(
                PasswordPolicyOutcome::deny(
                    PwdPolicyError::PASSWORD_EXPIRED,
                    ResultCode::INVALID_CREDENTIALS,
                    'Password has expired.',
                ),
                OperationalChanges::none(),
            );
        }

        $changes = $this->buildSuccessChanges(
            $state,
            $now,
            $isExpired,
        );
        $outcome = $this->composeSuccessOutcome(
            $state,
            $policy,
            $secondsRemaining,
            $isExpired,
        );

        return new RecordedOutcome(
            $outcome,
            OperationalChanges::of(...$changes),
        );
    }

    /**
     * Seconds remaining until pwdChangedTime + pwdMaxAge; null when expiration isn't configured or pwdChangedTime is
     * missing.
     *
     * Note: negative means already expired.
     */
    private function secondsUntilExpiration(
        UserPasswordState $state,
        PasswordPolicy $policy,
    ): ?int {
        $maxAge = $policy->expiration->maxAge;
        if ($maxAge === null || $maxAge === 0 || $state->changedAt === null) {
            return null;
        }

        $age = $this->clock->now()->getTimestamp()
            - $state->changedAt->getTimestamp();

        return $maxAge - $age;
    }

    /**
     * Number of grace logins still available. 0 means none left (or no grace configured).
     */
    private function graceRemaining(
        UserPasswordState $state,
        PasswordPolicy $policy,
    ): int {
        $limit = $policy->expiration->graceAuthnLimit;
        if ($limit === null || $limit === 0) {
            return 0;
        }

        return max(
            0,
            $limit - count($state->graceUseTimes),
        );
    }

    /**
     * @return list<Change>
     */
    private function buildSuccessChanges(
        UserPasswordState $state,
        DateTimeImmutable $now,
        bool $isExpired,
    ): array {
        $changes = [];

        if ($state->failureTimes !== []) {
            $changes[] = Change::reset(PasswordPolicyOid::NAME_PWD_FAILURE_TIME);
        }
        if ($state->accountLockedAt !== null && !$state->permanentlyLocked) {
            $changes[] = Change::reset(PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME);
        }
        if ($isExpired) {
            $graceTimes = [...$state->graceUseTimes, $now];
            $changes[] = Change::replace(
                PasswordPolicyOid::NAME_PWD_GRACE_USE_TIME,
                ...self::formatTimes($graceTimes),
            );
        }

        return $changes;
    }

    private function composeSuccessOutcome(
        UserPasswordState $state,
        PasswordPolicy $policy,
        ?int $secondsRemaining,
        bool $isExpired,
    ): PasswordPolicyOutcome {
        $errorCode = $state->mustChange ? PwdPolicyError::CHANGE_AFTER_RESET : null;
        $graceWarning = $isExpired
            ? $this->graceRemaining($state, $policy) - 1
            : null;
        $expirationWarning = $isExpired
            ? null
            : $this->expirationWarningSeconds($secondsRemaining, $policy);

        return new PasswordPolicyOutcome(
            denied: false,
            errorCode: $errorCode,
            timeBeforeExpiration: $expirationWarning,
            graceRemaining: $graceWarning,
        );
    }

    private function expirationWarningSeconds(
        ?int $secondsRemaining,
        PasswordPolicy $policy,
    ): ?int {
        $window = $policy->expiration->expireWarning;
        if ($secondsRemaining === null || $window === null || $window === 0) {
            return null;
        }
        if ($secondsRemaining > $window) {
            return null;
        }

        return $secondsRemaining;
    }

    /**
     * Evaluate a password change against the configured constraint chain.
     */
    public function evaluatePasswordChange(
        #[SensitiveParameter]
        string $newPassword,
        #[SensitiveParameter]
        ?string $oldPassword,
        UserPasswordState $state,
        PasswordPolicy $policy,
        bool $isSelf,
    ): PasswordPolicyOutcome {
        $attempt = new PasswordChangeAttempt(
            newPassword: $newPassword,
            oldPassword: $oldPassword,
            state: $state,
            policy: $policy,
            isSelf: $isSelf,
        );

        return $this->changeConstraints->evaluate($attempt)
            ?? PasswordPolicyOutcome::allow();
    }

    /**
     * Stamp pwdChangedTime, rotate pwdHistory, clear pwdReset / pwdFailureTime / pwdAccountLockedTime / pwdGraceUseTime.
     */
    public function recordPasswordChange(
        string $hashedNew,
        UserPasswordState $state,
        PasswordPolicy $policy,
    ): OperationalChanges {
        $now = $this->clock->now();
        $changes = [Change::replace(
            PasswordPolicyOid::NAME_PWD_CHANGED_TIME,
            GeneralizedTime::format($now),
        )];

        $historyChange = $this->buildHistoryChange(
            $hashedNew,
            $state,
            $policy,
            $now,
        );
        if ($historyChange !== null) {
            $changes[] = $historyChange;
        }
        if ($state->mustChange) {
            $changes[] = Change::reset(PasswordPolicyOid::NAME_PWD_RESET);
        }
        if ($state->failureTimes !== []) {
            $changes[] = Change::reset(PasswordPolicyOid::NAME_PWD_FAILURE_TIME);
        }
        if ($state->isLocked()) {
            $changes[] = Change::reset(PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME);
        }
        if ($state->graceUseTimes !== []) {
            $changes[] = Change::reset(PasswordPolicyOid::NAME_PWD_GRACE_USE_TIME);
        }

        return OperationalChanges::of(...$changes);
    }

    private function buildHistoryChange(
        string $hashedNew,
        UserPasswordState $state,
        PasswordPolicy $policy,
        DateTimeImmutable $now,
    ): ?Change {
        $depth = $policy->quality->inHistory;
        if ($depth === null || $depth === 0) {
            return null;
        }

        $newest = HistoryEntry::forStoredPassword(
            $now,
            $hashedNew,
        );
        $retained = array_slice(
            [$newest, ...$state->history],
            0,
            $depth,
        );

        return Change::replace(
            PasswordPolicyOid::NAME_PWD_HISTORY,
            ...array_map(
                static fn(HistoryEntry $entry): string => $entry->encode(),
                $retained,
            ),
        );
    }

    private function secondsSinceLock(UserPasswordState $state): int
    {
        if ($state->accountLockedAt === null) {
            return 0;
        }

        return $this->clock->now()->getTimestamp()
            - $state->accountLockedAt->getTimestamp();
    }

    /**
     * @param list<DateTimeImmutable> $instants
     * @return list<string>
     */
    private static function formatTimes(array $instants): array
    {
        return array_values(array_map(
            static fn(DateTimeImmutable $t): string => GeneralizedTime::format($t),
            $instants,
        ));
    }

    private static function denyLocked(): PasswordPolicyOutcome
    {
        return PasswordPolicyOutcome::deny(
            PwdPolicyError::ACCOUNT_LOCKED,
            ResultCode::INVALID_CREDENTIALS,
            'Account is locked.',
        );
    }
}
