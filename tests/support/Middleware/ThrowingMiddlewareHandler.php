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

use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use Throwable;

/**
 * Terminal handler that throws the given throwable instead of producing a result.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ThrowingMiddlewareHandler implements MiddlewareHandlerInterface
{
    public function __construct(private Throwable $throwable) {}

    public function handle(ServerRequestContext $context): OperationResult
    {
        throw $this->throwable;
    }
}
