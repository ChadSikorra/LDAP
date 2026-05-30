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

namespace FreeDSx\Ldap\Server\Proxy;

use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerProtocolHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationResult;

/**
 * Proxy request pipeline: handles StartTLS locally and forwards everything else.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ProxyRequestPipeline implements MiddlewareHandlerInterface
{
    public function __construct(
        private ServerProtocolHandlerInterface $startTlsHandler,
        private MiddlewareHandlerInterface $forwarder,
    ) {}

    /**
     * {@inheritDoc}
     */
    public function handle(ServerRequestContext $context): OperationResult
    {
        $request = $context->message->getRequest();

        if ($request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_START_TLS) {
            return $this->startTlsHandler->handleRequest(
                $context->message,
                $context->token,
            );
        }

        return $this->forwarder->handle($context);
    }
}
