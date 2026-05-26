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

use FreeDSx\Ldap\Server\Logging\OperationAuditor;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\AuditableResult;
use FreeDSx\Ldap\Server\Operation\OperationResult;

/**
 * Audits the operation outcome the handler propagates back up the pipeline.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class OperationAuditMiddleware implements MiddlewareInterface
{
    public function __construct(private OperationAuditor $auditor) {}

    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): OperationResult {
        $result = $next->handle($context);

        if ($result instanceof AuditableResult) {
            $result->record(
                $this->auditor,
                $context->token,
            );
        }

        return $result;
    }
}
