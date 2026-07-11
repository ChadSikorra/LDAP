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
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolations;
use FreeDSx\Ldap\Server\Logging\OperationAuditor;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * The outcome of a dispatched write, carrying any schema violations collected during it.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class WriteOperationResult implements AuditableResult
{
    private function __construct(
        private LdapMessageRequest $message,
        private SchemaViolations $schemaViolations,
    ) {}

    public static function success(
        LdapMessageRequest $message,
        SchemaViolations $schemaViolations,
    ): self {
        return new self(
            $message,
            $schemaViolations,
        );
    }

    public function outcome(): OperationOutcome
    {
        return OperationOutcome::Succeeded;
    }

    public function resultCode(): int
    {
        return ResultCode::SUCCESS;
    }

    public function record(
        OperationAuditor $auditor,
        TokenInterface $token,
    ): void {
        $auditor->recordSchemaViolations(
            $this->schemaViolations,
            $this->message,
            $token,
        );

        $auditor->recordWriteSuccess(
            $this->message,
            $token,
        );
    }
}
