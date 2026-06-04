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

use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Server\Logging\OperationAuditor;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * The outcome of a successful compare, carrying the match result.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class CompareOperationResult implements AuditableResult
{
    private function __construct(
        private LdapMessageRequest $message,
        private bool $match,
    ) {}

    public static function completed(
        LdapMessageRequest $message,
        bool $match,
    ): self {
        return new self(
            $message,
            $match,
        );
    }

    public function outcome(): OperationOutcome
    {
        return OperationOutcome::Succeeded;
    }

    public function resultCode(): int
    {
        return $this->match
            ? ResultCode::COMPARE_TRUE
            : ResultCode::COMPARE_FALSE;
    }

    public function record(
        OperationAuditor $auditor,
        TokenInterface $token,
    ): void {
        $auditor->recordCompareCompleted(
            $this->message,
            $this->match,
            $token,
        );
    }
}
