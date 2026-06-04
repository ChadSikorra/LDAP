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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Server\Logging\OperationAuditor;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * The outcome of a search, carrying the entries returned on success.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SearchOperationResult implements AuditableResult
{
    private function __construct(
        private LdapMessageRequest $message,
        private int $entriesReturned = 0,
        private ?OperationException $failure = null,
    ) {}

    public static function success(
        LdapMessageRequest $message,
        int $entriesReturned,
    ): self {
        return new self(
            $message,
            $entriesReturned,
        );
    }

    public static function failure(
        LdapMessageRequest $message,
        OperationException $exception,
    ): self {
        return new self(
            $message,
            failure: $exception,
        );
    }

    public function outcome(): OperationOutcome
    {
        return $this->failure === null
            ? OperationOutcome::Succeeded
            : OperationOutcome::Failed;
    }

    public function resultCode(): int
    {
        return $this->failure?->getCode() ?? ResultCode::SUCCESS;
    }

    public function record(
        OperationAuditor $auditor,
        TokenInterface $token,
    ): void {
        if ($this->failure !== null) {
            $auditor->recordSearchFailure(
                $this->message,
                $this->failure,
                $token,
            );

            return;
        }

        $auditor->recordSearchSuccess(
            $this->message,
            $this->entriesReturned,
            $token,
        );
    }
}
