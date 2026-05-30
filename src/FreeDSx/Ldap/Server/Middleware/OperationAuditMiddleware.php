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

namespace FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\SchemaRuleException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\Logging\OperationAuditor;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\AuditableResult;
use FreeDSx\Ldap\Server\Operation\OperationResult;

/**
 * Audits every operation outcome (the success result, or a thrown failure) the pipeline propagates back up.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class OperationAuditMiddleware implements MiddlewareInterface
{
    public function __construct(private OperationAuditor $auditor) {}

    /**
     * @throws OperationException
     */
    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): OperationResult {
        try {
            $result = $next->handle($context);
        } catch (OperationException $e) {
            $this->recordFailure(
                $context,
                $e,
            );

            throw $e;
        }

        if ($result instanceof AuditableResult) {
            $result->record(
                $this->auditor,
                $context->token,
            );
        }

        return $result;
    }

    private function recordFailure(
        ServerRequestContext $context,
        OperationException $e,
    ): void {
        if ($e instanceof SchemaRuleException) {
            $this->auditor->recordSchemaViolations(
                $e->getViolations(),
                $context->message,
                $context->token,
            );
        }

        if ($context->message->getRequest() instanceof SearchRequest) {
            $this->auditor->recordSearchFailure(
                $context->message,
                $e,
                $context->token,
            );

            return;
        }

        $this->auditor->recordFailure(
            $context->message,
            $e,
            $context->token,
        );
    }
}
