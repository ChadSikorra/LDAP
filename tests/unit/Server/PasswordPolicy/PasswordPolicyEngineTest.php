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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\HistoryEntry;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordExpirationRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordLockoutRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;
use Tests\Support\FreeDSx\Ldap\Server\PasswordPolicy\RecordingPasswordChangeConstraint;

final class PasswordPolicyEngineTest extends TestCase
{
    private const NOW = '2026-05-20T12:00:00Z';

    private FrozenClock $clock;
    private PasswordPolicyEngine $subject;

    protected function setUp(): void
    {
        $this->clock = FrozenClock::fromString(self::NOW);
        $this->subject = new PasswordPolicyEngine(
            clock: $this->clock,
            changeConstraints: new PasswordChangeConstraintChain([]),
        );
    }

    public function test_evaluatePreBind_unlocked_account_allows(): void
    {
        $outcome = $this->subject->evaluatePreBind(
            new UserPasswordState(),
            new PasswordPolicy(),
        );

        self::assertFalse($outcome->denied);
    }

    public function test_evaluatePreBind_permanently_locked_denies(): void
    {
        $outcome = $this->subject->evaluatePreBind(
            new UserPasswordState(permanentlyLocked: true),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    duration: 3600,
                ),
            ),
        );

        self::assertTrue($outcome->denied);
        self::assertSame(
            PwdPolicyError::ACCOUNT_LOCKED,
            $outcome->errorCode,
        );
        self::assertSame(
            ResultCode::INVALID_CREDENTIALS,
            $outcome->ldapResultCode,
        );
    }

    public function test_evaluatePreBind_locked_without_duration_denies(): void
    {
        $outcome = $this->subject->evaluatePreBind(
            new UserPasswordState(accountLockedAt: $this->minutesAgo(5)),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(enabled: true),
            ),
        );

        self::assertTrue($outcome->denied);
        self::assertSame(
            PwdPolicyError::ACCOUNT_LOCKED,
            $outcome->errorCode,
        );
    }

    public function test_evaluatePreBind_locked_within_duration_denies(): void
    {
        $outcome = $this->subject->evaluatePreBind(
            new UserPasswordState(accountLockedAt: $this->minutesAgo(5)),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    duration: 3600,
                ),
            ),
        );

        self::assertTrue($outcome->denied);
    }

    public function test_evaluatePreBind_locked_past_duration_allows(): void
    {
        $outcome = $this->subject->evaluatePreBind(
            new UserPasswordState(accountLockedAt: $this->minutesAgo(120)),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    duration: 3600,
                ),
            ),
        );

        self::assertFalse($outcome->denied);
    }

    public function test_recordBindFailure_appends_failure_time(): void
    {
        $result = $this->subject->recordBindFailure(
            new UserPasswordState(),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    maxFailure: 3,
                ),
            ),
        );

        self::assertFalse($result->outcome->denied);
        $change = $this->findChange(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
        );
        self::assertSame(
            [GeneralizedTime::format($this->clock->now())],
            $change->getAttribute()->getValues(),
        );
    }

    public function test_recordBindFailure_trims_failures_outside_interval(): void
    {
        $stale = $this->minutesAgo(120);
        $recent = $this->minutesAgo(2);

        $result = $this->subject->recordBindFailure(
            new UserPasswordState(failureTimes: [
                $stale,
                $recent,
            ]),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    maxFailure: 5,
                    failureCountInterval: 3600,
                ),
            ),
        );

        $change = $this->findChange(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
        );
        self::assertSame(
            [
                GeneralizedTime::format($recent),
                GeneralizedTime::format($this->clock->now()),
            ],
            $change->getAttribute()->getValues(),
        );
    }

    public function test_recordBindFailure_at_threshold_trips_lockout(): void
    {
        $result = $this->subject->recordBindFailure(
            new UserPasswordState(failureTimes: [
                $this->minutesAgo(3),
                $this->minutesAgo(2),
            ]),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    maxFailure: 3,
                ),
            ),
        );

        self::assertTrue($result->outcome->denied);
        self::assertSame(
            PwdPolicyError::ACCOUNT_LOCKED,
            $result->outcome->errorCode,
        );
        $lockChange = $this->findChange(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
        );
        self::assertSame(
            [GeneralizedTime::format($this->clock->now())],
            $lockChange->getAttribute()->getValues(),
        );
    }

    public function test_recordBindFailure_below_threshold_does_not_lock(): void
    {
        $result = $this->subject->recordBindFailure(
            new UserPasswordState(failureTimes: [$this->minutesAgo(2)]),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    maxFailure: 3,
                ),
            ),
        );

        self::assertFalse($result->outcome->denied);
        self::assertNull($this->findChangeOrNull(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
        ));
    }

    public function test_recordBindFailure_lockout_disabled_never_trips(): void
    {
        $result = $this->subject->recordBindFailure(
            new UserPasswordState(failureTimes: [
                $this->minutesAgo(3),
                $this->minutesAgo(2),
            ]),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: false,
                    maxFailure: 3,
                ),
            ),
        );

        self::assertFalse($result->outcome->denied);
        self::assertNull($this->findChangeOrNull(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
        ));
    }

    public function test_recordBindFailure_already_locked_does_not_re_lock(): void
    {
        $result = $this->subject->recordBindFailure(
            new UserPasswordState(
                accountLockedAt: $this->minutesAgo(5),
                failureTimes: [
                    $this->minutesAgo(3),
                    $this->minutesAgo(2),
                ],
            ),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    maxFailure: 3,
                ),
            ),
        );

        self::assertFalse($result->outcome->denied);
        self::assertNull($this->findChangeOrNull(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
        ));
    }

    public function test_recordBindSuccess_no_state_emits_no_changes(): void
    {
        $result = $this->subject->recordBindSuccess(
            new UserPasswordState(),
            new PasswordPolicy(),
        );

        self::assertFalse($result->outcome->denied);
        self::assertTrue($result->changes->isEmpty());
    }

    public function test_recordBindSuccess_clears_prior_failures_and_lock(): void
    {
        $result = $this->subject->recordBindSuccess(
            new UserPasswordState(
                accountLockedAt: $this->minutesAgo(120),
                failureTimes: [$this->minutesAgo(5)],
            ),
            new PasswordPolicy(
                lockout: new PasswordLockoutRules(
                    enabled: true,
                    duration: 3600,
                ),
            ),
        );

        self::assertTrue($this->findChange(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
        )->isReset());
        self::assertTrue($this->findChange(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
        )->isReset());
    }

    public function test_recordBindSuccess_does_not_clear_permanent_lock(): void
    {
        $result = $this->subject->recordBindSuccess(
            new UserPasswordState(permanentlyLocked: true),
            new PasswordPolicy(),
        );

        self::assertNull($this->findChangeOrNull(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
        ));
    }

    public function test_recordBindSuccess_expired_with_no_grace_denies(): void
    {
        $result = $this->subject->recordBindSuccess(
            new UserPasswordState(changedAt: $this->minutesAgo(120)),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(maxAge: 3600),
            ),
        );

        self::assertTrue($result->outcome->denied);
        self::assertSame(
            PwdPolicyError::PASSWORD_EXPIRED,
            $result->outcome->errorCode,
        );
        self::assertTrue($result->changes->isEmpty());
    }

    public function test_recordBindSuccess_expired_within_grace_returns_remaining(): void
    {
        $result = $this->subject->recordBindSuccess(
            new UserPasswordState(changedAt: $this->minutesAgo(120)),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(
                    maxAge: 3600,
                    graceAuthnLimit: 3,
                ),
            ),
        );

        self::assertFalse($result->outcome->denied);
        self::assertSame(
            2,
            $result->outcome->graceRemaining,
        );
        $graceChange = $this->findChange(
            $result->changes->changes,
            PasswordPolicyOid::NAME_PWD_GRACE_USE_TIME,
        );
        self::assertSame(
            [GeneralizedTime::format($this->clock->now())],
            $graceChange->getAttribute()->getValues(),
        );
    }

    public function test_recordBindSuccess_within_warning_returns_seconds_remaining(): void
    {
        $result = $this->subject->recordBindSuccess(
            new UserPasswordState(changedAt: $this->minutesAgo(50)),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(
                    maxAge: 3600,
                    expireWarning: 1200,
                ),
            ),
        );

        self::assertFalse($result->outcome->denied);
        self::assertSame(
            600,
            $result->outcome->timeBeforeExpiration,
        );
    }

    public function test_recordBindSuccess_outside_warning_window_returns_null(): void
    {
        $result = $this->subject->recordBindSuccess(
            new UserPasswordState(changedAt: $this->minutesAgo(10)),
            new PasswordPolicy(
                expiration: new PasswordExpirationRules(
                    maxAge: 3600,
                    expireWarning: 600,
                ),
            ),
        );

        self::assertNull($result->outcome->timeBeforeExpiration);
    }

    public function test_recordBindSuccess_must_change_propagates_error_code(): void
    {
        $result = $this->subject->recordBindSuccess(
            new UserPasswordState(mustChange: true),
            new PasswordPolicy(),
        );

        self::assertFalse($result->outcome->denied);
        self::assertSame(
            PwdPolicyError::CHANGE_AFTER_RESET,
            $result->outcome->errorCode,
        );
    }

    public function test_evaluatePasswordChange_delegates_to_constraint_chain(): void
    {
        $deny = PasswordPolicyOutcome::deny(
            PwdPolicyError::PASSWORD_TOO_SHORT,
            ResultCode::CONSTRAINT_VIOLATION,
            'denied',
        );
        $engine = $this->engineWith($this->stubConstraint($deny));

        $outcome = $engine->evaluatePasswordChange(
            newPassword: 'newpw',
            oldPassword: null,
            state: new UserPasswordState(),
            policy: new PasswordPolicy(),
            isSelf: true,
        );

        self::assertSame(
            $deny,
            $outcome,
        );
    }

    public function test_evaluatePasswordChange_chain_null_returns_allow(): void
    {
        $outcome = $this
            ->engineWith($this->stubConstraint(null))
            ->evaluatePasswordChange(
                newPassword: 'newpw',
                oldPassword: null,
                state: new UserPasswordState(),
                policy: new PasswordPolicy(),
                isSelf: true,
            );

        self::assertFalse($outcome->denied);
    }

    public function test_evaluatePasswordChange_passes_attempt_through(): void
    {
        $state = new UserPasswordState();
        $policy = new PasswordPolicy();
        $constraint = new RecordingPasswordChangeConstraint();

        $this->engineWith($constraint)->evaluatePasswordChange(
            newPassword: 'newpw',
            oldPassword: 'oldpw',
            state: $state,
            policy: $policy,
            isSelf: false,
        );

        self::assertCount(
            1,
            $constraint->invocations,
        );
        $attempt = $constraint->invocations[0];
        self::assertSame(
            'newpw',
            $attempt->newPassword,
        );
        self::assertSame(
            'oldpw',
            $attempt->oldPassword,
        );
        self::assertSame(
            $state,
            $attempt->state,
        );
        self::assertSame(
            $policy,
            $attempt->policy,
        );
        self::assertFalse($attempt->isSelf);
    }

    public function test_recordPasswordChange_stamps_changed_time(): void
    {
        $changes = $this->subject->recordPasswordChange(
            '{BCRYPT}hashed',
            new UserPasswordState(),
            new PasswordPolicy(),
        );

        $change = $this->findChange(
            $changes->changes,
            PasswordPolicyOid::NAME_PWD_CHANGED_TIME,
        );
        self::assertSame(
            [GeneralizedTime::format($this->clock->now())],
            $change->getAttribute()->getValues(),
        );
    }

    public function test_recordPasswordChange_zero_history_emits_no_history_change(): void
    {
        $changes = $this->subject->recordPasswordChange(
            '{BCRYPT}hashed',
            new UserPasswordState(),
            new PasswordPolicy(
                quality: new PasswordQualityRules(inHistory: 0),
            ),
        );

        self::assertNull($this->findChangeOrNull(
            $changes->changes,
            PasswordPolicyOid::NAME_PWD_HISTORY,
        ));
    }

    public function test_recordPasswordChange_prepends_and_trims_history(): void
    {
        $oldest = $this->historyEntry(
            $this->minutesAgo(180),
            '{BCRYPT}old1',
        );
        $newer = $this->historyEntry(
            $this->minutesAgo(60),
            '{BCRYPT}old2',
        );

        $changes = $this->subject->recordPasswordChange(
            '{BCRYPT}brand-new',
            new UserPasswordState(history: [
                $newer,
                $oldest,
            ]),
            new PasswordPolicy(
                quality: new PasswordQualityRules(inHistory: 2),
            ),
        );

        $historyChange = $this->findChange(
            $changes->changes,
            PasswordPolicyOid::NAME_PWD_HISTORY,
        );
        $values = $historyChange->getAttribute()->getValues();
        self::assertCount(
            2,
            $values,
        );
        self::assertStringContainsString(
            '{BCRYPT}brand-new',
            $values[0],
        );
        self::assertStringContainsString(
            '{BCRYPT}old2',
            $values[1],
        );
    }

    public function test_recordPasswordChange_clears_must_change_failure_and_lock(): void
    {
        $changes = $this->subject->recordPasswordChange(
            '{BCRYPT}hashed',
            new UserPasswordState(
                accountLockedAt: $this->minutesAgo(5),
                failureTimes: [$this->minutesAgo(2)],
                graceUseTimes: [$this->minutesAgo(1)],
                mustChange: true,
            ),
            new PasswordPolicy(),
        );

        self::assertTrue($this->findChange(
            $changes->changes,
            PasswordPolicyOid::NAME_PWD_RESET,
        )->isReset());
        self::assertTrue($this->findChange(
            $changes->changes,
            PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
        )->isReset());
        self::assertTrue($this->findChange(
            $changes->changes,
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
        )->isReset());
        self::assertTrue($this->findChange(
            $changes->changes,
            PasswordPolicyOid::NAME_PWD_GRACE_USE_TIME,
        )->isReset());
    }

    public function test_recordPasswordChange_clean_state_emits_only_changed_time(): void
    {
        $changes = $this->subject->recordPasswordChange(
            '{BCRYPT}hashed',
            new UserPasswordState(),
            new PasswordPolicy(
                quality: new PasswordQualityRules(inHistory: 0),
            ),
        );

        self::assertCount(
            1,
            $changes->changes,
        );
        self::assertSame(
            PasswordPolicyOid::NAME_PWD_CHANGED_TIME,
            $changes->changes[0]->getAttribute()->getName(),
        );
    }

    private function engineWith(PasswordChangeConstraint $constraint): PasswordPolicyEngine
    {
        return new PasswordPolicyEngine(
            clock: $this->clock,
            changeConstraints: new PasswordChangeConstraintChain([$constraint]),
        );
    }

    private function minutesAgo(int $minutes): DateTimeImmutable
    {
        return $this->clock
            ->now()
            ->sub(new DateInterval(sprintf('PT%dM', $minutes)));
    }

    /**
     * @param list<Change> $changes
     */
    private function findChange(
        array $changes,
        string $name,
    ): Change {
        $found = $this->findChangeOrNull(
            $changes,
            $name,
        );
        self::assertNotNull(
            $found,
            sprintf('Expected change for "%s" in operational changes.', $name),
        );

        return $found;
    }

    /**
     * @param list<Change> $changes
     */
    private function findChangeOrNull(
        array $changes,
        string $name,
    ): ?Change {
        foreach ($changes as $change) {
            if (strcasecmp($change->getAttribute()->getName(), $name) === 0) {
                return $change;
            }
        }

        return null;
    }

    private function historyEntry(
        DateTimeImmutable $when,
        string $stored,
    ): HistoryEntry {
        return HistoryEntry::forStoredPassword(
            $when->setTimezone(new DateTimeZone('UTC')),
            $stored,
        );
    }

    private function stubConstraint(?PasswordPolicyOutcome $outcome): PasswordChangeConstraint
    {
        $stub = $this->createMock(PasswordChangeConstraint::class);
        $stub
            ->method('check')
            ->willReturn($outcome);

        return $stub;
    }
}
