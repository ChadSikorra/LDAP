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
 * Nests an ordered list of middleware around a terminal handler.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class MiddlewareChain implements MiddlewareHandlerInterface
{
    private MiddlewareHandlerInterface $pipeline;

    /**
     * @param list<MiddlewareInterface> $middleware
     */
    public function __construct(
        array $middleware,
        MiddlewareHandlerInterface $terminal,
    ) {
        $pipeline = $terminal;
        foreach (array_reverse($middleware) as $item) {
            $pipeline = new ChainStep(
                $item,
                $pipeline,
            );
        }

        $this->pipeline = $pipeline;
    }

    public function handle(ServerRequestContext $context): void
    {
        $this->pipeline->handle($context);
    }
}
