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

namespace FreeDSx\Ldap\Server\Operation;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Server\Logging\OperationAuditor;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * The outcome of a password modify, carrying the resolved target when known.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PasswordModifyOperationResult implements AuditableResult
{
    private function __construct(
        private LdapMessageRequest $message,
        private ?Dn $targetDn = null,
        private ?OperationException $failure = null,
    ) {}

    public static function success(
        LdapMessageRequest $message,
        Dn $targetDn,
    ): self {
        return new self(
            $message,
            $targetDn,
        );
    }

    public static function failure(
        LdapMessageRequest $message,
        OperationException $exception,
        ?Dn $targetDn = null,
    ): self {
        return new self(
            $message,
            $targetDn,
            $exception,
        );
    }

    public function outcome(): OperationOutcome
    {
        return $this->failure === null
            ? OperationOutcome::Succeeded
            : OperationOutcome::Failed;
    }

    public function record(
        OperationAuditor $auditor,
        TokenInterface $token,
    ): void {
        if ($this->failure !== null) {
            $auditor->recordPasswordModifyFailure(
                $this->message,
                $this->failure,
                $this->targetDn,
                $token,
            );

            return;
        }

        if ($this->targetDn !== null) {
            $auditor->recordPasswordModifySuccess(
                $this->message,
                $this->targetDn,
                $token,
            );
        }
    }
}
