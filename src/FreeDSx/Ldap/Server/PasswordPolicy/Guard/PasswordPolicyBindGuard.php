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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Guard;

use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\Backend\Write\SystemChangeWriterInterface;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\PasswordPolicy\Attempt\PasswordBindAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;

/**
 * Applies the engine's bind-time decisions.
 */
final readonly class PasswordPolicyBindGuard
{
    public function __construct(
        private PasswordPolicyEngine $engine,
        private SystemChangeWriterInterface $writer,
        private PasswordPolicyContext $context,
        private EventLogger $eventLogger,
        private SleeperInterface $sleeper,
    ) {}

    /**
     * @throws OperationException when the account is locked and may not yet attempt a bind.
     */
    public function preBind(PasswordBindAttempt $attempt): void
    {
        $outcome = $this->engine->evaluatePreBind(
            $attempt->state,
            $attempt->policy,
        );
        if (!$outcome->denied) {
            return;
        }

        $this->context->setOutcome($outcome);
        $this->eventLogger->record(
            ServerEvent::PasswordPolicyAccountLocked,
            $this->subjectFor($attempt),
        );

        throw new OperationException(
            $outcome->diagnostic,
            $outcome->ldapResultCode,
        );
    }

    /**
     * Surfaces a lockout outcome but never throws (the caller re-throws the credential error), then applies the
     * configured pwdMinDelay/pwdMaxDelay response delay.
     */
    public function recordFailure(PasswordBindAttempt $attempt): void
    {
        $recorded = $this->engine->recordBindFailure(
            $attempt->state,
            $attempt->policy,
        );
        $this->writer->write(
            $attempt->dn,
            $recorded->changes,
        );

        if ($recorded->outcome->denied) {
            $this->context->setOutcome($recorded->outcome);
            $this->eventLogger->record(
                ServerEvent::PasswordPolicyAccountLocked,
                $this->subjectFor($attempt),
            );
        }

        $this->sleeper->sleep($recorded->delaySeconds);
    }

    /**
     * @throws OperationException when the password is expired with no grace logins remaining.
     */
    public function recordSuccess(PasswordBindAttempt $attempt): void
    {
        $recorded = $this->engine->recordBindSuccess(
            $attempt->state,
            $attempt->policy,
        );
        $outcome = $recorded->outcome;

        if ($outcome->denied) {
            $this->context->setOutcome($outcome);
            $this->eventLogger->record(
                ServerEvent::PasswordPolicyExpired,
                $this->subjectFor($attempt),
            );

            throw new OperationException(
                $outcome->diagnostic,
                $outcome->ldapResultCode,
            );
        }

        $this->writer->write(
            $attempt->dn,
            $recorded->changes,
        );
        $this->context->setOutcome($outcome);
        $this->emitSuccessEvents(
            $attempt,
            $outcome,
        );
    }

    private function emitSuccessEvents(
        PasswordBindAttempt $attempt,
        PasswordPolicyOutcome $outcome,
    ): void {
        $subject = $this->subjectFor($attempt);

        if ($attempt->state->isLocked() && !$attempt->state->permanentlyLocked) {
            $this->eventLogger->record(
                ServerEvent::PasswordPolicyAccountUnlocked,
                $subject,
            );
        }
        if ($outcome->graceRemaining !== null) {
            $this->eventLogger->record(
                ServerEvent::PasswordPolicyGraceLogin,
                $subject,
            );
        }
        if ($outcome->errorCode === PwdPolicyError::CHANGE_AFTER_RESET) {
            $this->eventLogger->record(
                ServerEvent::PasswordPolicyMustChange,
                $subject,
            );
        }
    }

    /**
     * @return array<string, string>
     */
    private function subjectFor(PasswordBindAttempt $attempt): array
    {
        return [
            EventContext::USERNAME => $attempt->name,
            EventContext::DN => $attempt->dn->toString(),
        ];
    }
}
