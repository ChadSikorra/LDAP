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

use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\PasswordPolicy\RecordingPasswordChangeConstraint;

final class PasswordChangeConstraintChainTest extends TestCase
{
    public function test_empty_chain_returns_null(): void
    {
        $chain = new PasswordChangeConstraintChain([]);

        self::assertNull($chain->evaluate($this->attempt()));
    }

    public function test_all_passing_constraints_return_null(): void
    {
        $passing = $this->stubConstraint(null);

        $chain = new PasswordChangeConstraintChain([
            $passing,
            $passing,
            $passing,
        ]);

        self::assertNull($chain->evaluate($this->attempt()));
    }

    public function test_first_denying_constraint_short_circuits(): void
    {
        $firstDeny = $this->stubConstraint(
            PasswordPolicyOutcome::deny(
                PwdPolicyError::PASSWORD_TOO_SHORT,
                ResultCode::CONSTRAINT_VIOLATION,
                'first',
            ),
        );
        $secondDeny = $this->stubConstraint(
            PasswordPolicyOutcome::deny(
                PwdPolicyError::PASSWORD_IN_HISTORY,
                ResultCode::CONSTRAINT_VIOLATION,
                'second',
            ),
        );

        $chain = new PasswordChangeConstraintChain([
            $firstDeny,
            $secondDeny,
        ]);

        $outcome = $chain->evaluate($this->attempt());

        self::assertNotNull($outcome);
        self::assertSame(
            PwdPolicyError::PASSWORD_TOO_SHORT,
            $outcome->errorCode,
        );
    }

    public function test_passing_chain_visits_every_constraint(): void
    {
        $first = new RecordingPasswordChangeConstraint();
        $second = new RecordingPasswordChangeConstraint();
        $third = new RecordingPasswordChangeConstraint();

        $chain = new PasswordChangeConstraintChain([
            $first,
            $second,
            $third,
        ]);
        $chain->evaluate($this->attempt());

        self::assertCount(
            1,
            $first->invocations,
        );
        self::assertCount(
            1,
            $second->invocations,
        );
        self::assertCount(
            1,
            $third->invocations,
        );
    }

    private function attempt(): PasswordChangeAttempt
    {
        return new PasswordChangeAttempt(
            newPassword: 'newpw',
            oldPassword: null,
            state: new UserPasswordState(),
            policy: new PasswordPolicy(),
            isSelf: true,
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
