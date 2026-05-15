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

use Exception;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles a whoami request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerWhoAmIHandler implements ServerProtocolHandlerInterface
{
    use ServerCriticalControlTrait;

    public function __construct(private readonly ServerQueue $queue) {}

    /**
     * {@inheritDoc}
     * @throws EncoderException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): void {
        $this->assertNoCriticalUnsupportedControls($message->controls());
        $userId = null;

        if ($token instanceof AuthenticatedTokenInterface) {
            $resolvedDn = $token->getResolvedDn();

            try {
                $resolvedDn->toArray();
                $userId = 'dn:' . $resolvedDn->toString();
            } catch (Exception) {
                $userId = 'u:' . $token->getUsername();
            }
        }

        $this->queue->sendMessage(new LdapMessageResponse(
            $message->getMessageId(),
            new ExtendedResponse(new LdapResult(ResultCode::SUCCESS), null, $userId),
        ));
    }
}
