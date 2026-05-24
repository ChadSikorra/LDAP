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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy\Constraint;

use DateTimeImmutable;
use DateTimeZone;
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\MinAgeConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordChangeRules;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;

final class MinAgeConstraintTest extends TestCase
{
    private const NOW = '2026-05-20T12:00:00Z';

    private FrozenClock $clock;
    private MinAgeConstraint $subject;

    protected function setUp(): void
    {
        $this->clock = FrozenClock::fromString(self::NOW);
        $this->subject = new MinAgeConstraint($this->clock);
    }

    public function test_unset_min_age_skips(): void
    {
        self::assertNull(
            $this->subject->check(
                $this->attempt(
                    minAge: null,
                    changedAt: $this->utc('2026-05-20T11:59:00Z'),
                ),
            ),
        );
    }

    public function test_zero_min_age_skips(): void
    {
        self::assertNull(
            $this->subject->check(
                $this->attempt(
                    minAge: 0,
                    changedAt: $this->utc('2026-05-20T11:59:00Z'),
                ),
            ),
        );
    }

    public function test_missing_changed_at_skips(): void
    {
        self::assertNull(
            $this->subject->check(
                $this->attempt(
                    minAge: 3600,
                    changedAt: null,
                ),
            ),
        );
    }

    public function test_age_within_min_age_denies(): void
    {
        $outcome = $this->subject->check(
            $this->attempt(
                minAge: 3600,
                changedAt: $this->utc('2026-05-20T11:30:00Z'),
            ),
        );

        self::assertNotNull($outcome);
        self::assertTrue($outcome->denied);
        self::assertSame(
            PwdPolicyError::PASSWORD_TOO_YOUNG,
            $outcome->errorCode,
        );
    }

    public function test_non_self_change_skips_min_age(): void
    {
        self::assertNull(
            $this->subject->check(
                $this->attempt(
                    minAge: 3600,
                    changedAt: $this->utc('2026-05-20T11:30:00Z'),
                    isSelf: false,
                ),
            ),
        );
    }

    public function test_age_exactly_at_boundary_passes(): void
    {
        self::assertNull(
            $this->subject->check(
                $this->attempt(
                    minAge: 3600,
                    changedAt: $this->utc('2026-05-20T11:00:00Z'),
                ),
            ),
        );
    }

    public function test_age_past_boundary_passes(): void
    {
        self::assertNull(
            $this->subject->check(
                $this->attempt(
                    minAge: 3600,
                    changedAt: $this->utc('2026-05-20T10:00:00Z'),
                ),
            ),
        );
    }

    /**
     * @param int<0, max>|null $minAge
     */
    private function attempt(
        ?int $minAge,
        ?DateTimeImmutable $changedAt,
        bool $isSelf = true,
    ): PasswordChangeAttempt {
        return new PasswordChangeAttempt(
            newPassword: 'newpw',
            oldPassword: null,
            state: new UserPasswordState(changedAt: $changedAt),
            policy: new PasswordPolicy(
                change: new PasswordChangeRules(minAge: $minAge),
            ),
            isSelf: $isSelf,
        );
    }

    private function utc(string $iso): DateTimeImmutable
    {
        return new DateTimeImmutable(
            $iso,
            new DateTimeZone('UTC'),
        );
    }
}
