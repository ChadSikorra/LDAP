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

namespace FreeDSx\Ldap\Server\Middleware\Pipeline;

/**
 * Binds a single middleware to the next handler in the chain.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ChainStep implements MiddlewareHandlerInterface
{
    public function __construct(
        private MiddlewareInterface $middleware,
        private MiddlewareHandlerInterface $next,
    ) {}

    public function handle(ServerRequestContext $context): void
    {
        $this->middleware->process(
            $context,
            $this->next,
        );
    }
}
