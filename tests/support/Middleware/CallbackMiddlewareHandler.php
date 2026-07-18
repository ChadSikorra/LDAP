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

namespace Tests\Support\FreeDSx\Ldap\Middleware;

use Closure;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationResult;

/**
 * Terminal handler that defers to a callback, letting a test observe state while the operation is in flight.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class CallbackMiddlewareHandler implements MiddlewareHandlerInterface
{
    /**
     * @param Closure(ServerRequestContext): OperationResult $callback
     */
    public function __construct(private Closure $callback) {}

    public function handle(ServerRequestContext $context): ResponseStream
    {
        return ResponseStream::resolved(($this->callback)($context));
    }
}
