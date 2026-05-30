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

/**
 * Terminal handler that returns a preconfigured result.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class StubMiddlewareHandler implements MiddlewareHandlerInterface
{
    public function __construct(private OperationResult $result) {}

    public function handle(ServerRequestContext $context): OperationResult
    {
        return $this->result;
    }
}
