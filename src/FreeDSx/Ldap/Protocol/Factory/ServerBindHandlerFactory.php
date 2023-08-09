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

namespace FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\BindHandlerInterface;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerAnonBindHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerBindHandler;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;

/**
 * Determines the correct bind handler for the request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerBindHandlerFactory
{
    public function __construct(
        private readonly ServerQueue $queue,
        private readonly HandlerFactoryInterface $handlerFactory,
    ) {
    }

    /**
     * Get the bind handler specific to the request.
     *
     * @throws OperationException
     */
    public function get(RequestInterface $request): BindHandlerInterface
    {
        if ($request instanceof SimpleBindRequest) {
            return new ServerBindHandler(
                queue: $this->queue,
                dispatcher: $this->handlerFactory->makeRequestHandler(),
            );
        } elseif ($request instanceof AnonBindRequest) {
            return new ServerAnonBindHandler($this->queue);
        } else {
            throw new OperationException(
                'The authentication type requested is not supported.',
                ResultCode::AUTH_METHOD_UNSUPPORTED
            );
        }
    }
}
