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

use FreeDSx\Ldap\Protocol\Factory\ProtocolHandlerProviderInterface;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseWriter;
use FreeDSx\Ldap\Server\Operation\OperationResult;

/**
 * Terminal handler that resolves the per-request handler, writes its response, and returns its outcome.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class HandlerInvoker implements MiddlewareHandlerInterface
{
    public function __construct(
        private ProtocolHandlerProviderInterface $protocolHandlerProvider,
        private ResponseWriter $responseWriter,
    ) {}

    public function handle(ServerRequestContext $context): OperationResult
    {
        $handler = $this->protocolHandlerProvider->get(
            $context->message->getRequest(),
            $context->message->controls(),
            $context->searchLimits(),
        );

        $stream = $handler->handleRequest(
            $context->message,
            $context->tokenOrFail(),
        );

        return $this->responseWriter->write(
            $stream,
            $context->message->getMessageId(),
        );
    }
}
