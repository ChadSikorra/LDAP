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

use FreeDSx\Ldap\Server\Operation\OperationResult;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\SearchLimit\SearchLimitResolverInterface;

/**
 * Resolves the per-identity search limits for the request and attaches them to the context.
 */
final readonly class ResourceLimitMiddleware implements MiddlewareInterface
{
    public function __construct(
        private SearchLimitResolverInterface $searchLimitResolver,
    ) {}

    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): OperationResult {
        $limits = $this->searchLimitResolver->resolve($context->tokenOrFail());

        return $next->handle($context->withSearchLimits($limits));
    }
}
