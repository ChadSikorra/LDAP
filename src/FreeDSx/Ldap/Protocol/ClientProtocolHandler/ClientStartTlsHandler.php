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

namespace FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;

/**
 * Logic for handling a StartTLS operation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientStartTlsHandler implements ResponseHandlerInterface
{
    public function __construct(private readonly ClientQueue $queue)
    {
    }

    /**
     * {@inheritDoc}
     * @throws ConnectionException
     * @throws \FreeDSx\Socket\Exception\ConnectionException
     */
    public function handleResponse(
        LdapMessageRequest $messageTo,
        LdapMessageResponse $messageFrom
    ): ?LdapMessageResponse {
        /** @var ExtendedResponse $response */
        $response = $messageFrom->getResponse();

        if ($response->getResultCode() !== ResultCode::SUCCESS) {
            throw new ConnectionException(sprintf(
                'Unable to start TLS: %s',
                $response->getDiagnosticMessage()
            ));
        }
        $this->queue->encrypt();

        return $messageFrom;
    }
}
