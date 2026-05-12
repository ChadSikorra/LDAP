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

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Protocol\Factory\ExtendedResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Socket\Exception\ConnectionException;

/**
 * Logic for handling extended operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientExtendedOperationHandler extends ClientBasicHandler
{
    private ExtendedResponseFactory $extendedResponseFactory;

    public function __construct(
        ClientQueue $queue,
        ?ExtendedResponseFactory $extendedResponseFactory = null,
    ) {
        $this->extendedResponseFactory = $extendedResponseFactory ?? new ExtendedResponseFactory();

        parent::__construct($queue);
    }

    /**
     * Re-decodes the extended response into its concrete subclass when the OID is registered.
     *
     * @throws OperationException
     */
    public function handleResponse(
        LdapMessageRequest $messageTo,
        LdapMessageResponse $messageFrom,
    ): ?LdapMessageResponse {
        /** @var ExtendedRequest $request */
        $request = $messageTo->getRequest();

        if (!$this->extendedResponseFactory->has($request->getName())) {
            return parent::handleResponse(
                $messageTo,
                $messageFrom,
            );
        }

        return parent::handleResponse(
            $messageTo,
            $this->redecodeResponse(
                $messageFrom,
                $request->getName(),
            ),
        );
    }

    /**
     * @throws OperationException
     * @throws EncoderException
     * @throws ProtocolException
     * @throws UnsolicitedNotificationException
     * @throws ConnectionException
     * @throws RuntimeException
     */
    public function handleRequest(LdapMessageRequest $message): ?LdapMessageResponse
    {
        $messageFrom = parent::handleRequest($message);

        /** @var ExtendedRequest $request */
        $request = $message->getRequest();
        if (!$this->extendedResponseFactory->has($request->getName())) {
            return $messageFrom;
        }
        if ($messageFrom === null) {
            throw new OperationException('Expected an LDAP message response, but none was received.');
        }

        return $this->redecodeResponse(
            $messageFrom,
            $request->getName(),
        );
    }

    private function redecodeResponse(
        LdapMessageResponse $message,
        string $oid,
    ): LdapMessageResponse {
        return new LdapMessageResponse(
            $message->getMessageId(),
            $this->extendedResponseFactory->get(
                $message->getResponse()->toAsn1(),
                $oid,
            ),
            ...$message->controls()->toArray(),
        );
    }
}
