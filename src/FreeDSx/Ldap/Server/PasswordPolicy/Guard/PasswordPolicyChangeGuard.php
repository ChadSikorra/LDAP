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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\PasswordPolicyException;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\PasswordPolicy\Attempt\PasswordModifyAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;

/**
 * Enforces password policy on a password change, returning deltas to persist alongside it.
 */
final readonly class PasswordPolicyChangeGuard
{
    public function __construct(
        private PasswordPolicyEngine $engine,
        private PasswordPolicyResolver $resolver,
        private PasswordPolicyContext $context,
        private EventLogger $eventLogger,
    ) {}

    /**
     * @throws OperationException|PasswordPolicyException when the new password violates the governing policy.
     */
    public function enforce(PasswordModifyAttempt $attempt): OperationalChanges
    {
        $policy = $this->resolver->resolveFor($attempt->target);
        if ($policy === null) {
            return OperationalChanges::none();
        }

        $state = UserPasswordState::fromEntry($attempt->target);
        $outcome = $this->engine->evaluatePasswordChange(
            $attempt->newPassword,
            $attempt->oldPassword,
            $state,
            $policy,
            $attempt->isSelf,
        );

        if ($outcome->denied) {
            $this->context->setOutcome($outcome);
            $this->eventLogger->record(
                ServerEvent::PasswordPolicyChangeRejected,
                [EventContext::TARGET => [EventContext::DN => $attempt->target->getDn()->toString()]],
            );

            throw new OperationException(
                $outcome->diagnostic,
                $outcome->ldapResultCode,
            );
        }

        return $this->engine->recordPasswordChange(
            $attempt->hashedNewPassword,
            $state,
            $policy,
        );
    }
}
