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
use FreeDSx\Ldap\Exception\SchemaRuleException;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Server\Logging\OperationAuditor;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * The outcome for an operation the response writer answered from a caught exception; audits by request type.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class FailedOperationResult implements AuditableResult
{
    public function __construct(
        private LdapMessageRequest $message,
        private OperationException $exception,
    ) {}

    public function outcome(): OperationOutcome
    {
        return OperationOutcome::Failed;
    }

    public function resultCode(): int
    {
        return $this->exception->getCode();
    }

    public function record(
        OperationAuditor $auditor,
        TokenInterface $token,
    ): void {
        if ($this->exception instanceof SchemaRuleException) {
            $auditor->recordSchemaViolations(
                $this->exception->getViolations(),
                $this->message,
                $token,
            );
        }

        $request = $this->message->getRequest();

        if ($request instanceof SearchRequest) {
            $auditor->recordSearchFailure(
                $this->message,
                $this->exception,
                $token,
            );

            return;
        }

        if ($request instanceof CompareRequest) {
            $auditor->recordCompareFailure(
                $this->message,
                $this->exception,
                $token,
            );

            return;
        }

        $auditor->recordFailure(
            $this->message,
            $this->exception,
            $token,
        );
    }
}
