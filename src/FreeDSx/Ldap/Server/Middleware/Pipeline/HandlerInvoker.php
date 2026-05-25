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

use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;

/**
 * Terminal handler that resolves and invokes the per-request protocol handler.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class HandlerInvoker implements MiddlewareHandlerInterface
{
    public function __construct(private ServerProtocolHandlerFactory $protocolHandlerFactory) {}

    public function handle(ServerRequestContext $context): void
    {
        $handler = $this->protocolHandlerFactory->get(
            $context->message->getRequest(),
            $context->message->controls(),
        );
        $handler->handleRequest(
            $context->message,
            $context->token,
        );
    }
}
