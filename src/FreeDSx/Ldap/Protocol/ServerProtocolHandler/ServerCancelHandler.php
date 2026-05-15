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
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles a CancelRequest (RFC 3909) that arrives after the target operation has already completed.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerCancelHandler implements ServerProtocolHandlerInterface
{
    use ServerCriticalControlTrait;

    public function __construct(private ServerQueue $queue) {}

    /**
     * {@inheritDoc}
     * @throws EncoderException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): void {
        $this->assertNoCriticalUnsupportedControls($message->controls());
        $this->queue->sendMessage(new LdapMessageResponse(
            $message->getMessageId(),
            new ExtendedResponse(new LdapResult(ResultCode::NO_SUCH_OPERATION)),
        ));
    }
}
