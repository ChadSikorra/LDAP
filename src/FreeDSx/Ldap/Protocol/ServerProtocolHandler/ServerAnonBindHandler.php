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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;

/**
 * Handles anonymous bind requests.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerAnonBindHandler extends ServerBindHandler
{
    /**
     * {@inheritDoc}
     * @throws EncoderException
     * @throws OperationException
     * @throws RuntimeException
     */
    public function handleBind(
        LdapMessageRequest $message,
        RequestHandlerInterface $dispatcher,
        ServerQueue $queue
    ): TokenInterface {
        $request = $message->getRequest();
        if (!$request instanceof AnonBindRequest) {
            throw new RuntimeException(sprintf(
                'Expected an AnonBindRequest, got: %s',
                get_class($request)
            ));
        }

        $this->validateVersion($request);
        $queue->sendMessage($this->responseFactory->getStandardResponse($message));

        return new AnonToken(
            $request->getUsername(),
            $request->getVersion()
        );
    }
}
