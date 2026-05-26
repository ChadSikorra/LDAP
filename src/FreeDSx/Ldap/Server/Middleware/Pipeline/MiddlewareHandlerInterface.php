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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use FreeDSx\Socket\Exception\ConnectionException;

/**
 * Handles a request at some point in the middleware pipeline (the "next" link).
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface MiddlewareHandlerInterface
{
    /**
     * @throws OperationException
     * @throws ConnectionException
     */
    public function handle(ServerRequestContext $context): OperationResult;
}
