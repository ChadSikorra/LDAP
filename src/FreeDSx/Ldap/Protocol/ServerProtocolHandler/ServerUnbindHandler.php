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

use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ConnectionControl;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles an un-bind. Which just closes the connection.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerUnbindHandler implements ServerProtocolHandlerInterface
{
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): ResponseStream {
        return ResponseStream::none(OperationOutcomeResult::succeeded())
            ->withOnComplete(static function (ConnectionControl $connection): void {
                $connection->close();
            });
    }
}
