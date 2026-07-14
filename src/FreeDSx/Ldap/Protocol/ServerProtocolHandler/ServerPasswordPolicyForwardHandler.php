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
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\PasswordPolicy\ForwardPasswordPolicyStateRequest;
use FreeDSx\Ldap\Operation\Request\PasswordPolicy\PasswordPolicyStateAttribute;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Backend\Write\SystemChange\SystemChangeWriterInterface;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Applies a replica-forwarded password-policy state delta as an internal system write, so it journals and replicates.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerPasswordPolicyForwardHandler implements ServerProtocolHandlerInterface
{
    public function __construct(
        private ServerQueue $queue,
        private SystemChangeWriterInterface $changeWriter,
    ) {}

    /**
     * {@inheritDoc}
     *
     * @throws EncoderException
     * @throws OperationException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): OperationResult {
        $request = $message->getRequest();
        if (!$request instanceof ForwardPasswordPolicyStateRequest) {
            throw new OperationException(
                'The password policy forward request is malformed.',
                ResultCode::PROTOCOL_ERROR,
            );
        }

        $this->changeWriter->write(
            $request->getDn(),
            $this->toOperationalChanges($request->getState()),
        );

        $this->queue->sendMessage(new LdapMessageResponse(
            $message->getMessageId(),
            new ExtendedResponse(new LdapResult(ResultCode::SUCCESS)),
        ));

        return OperationOutcomeResult::succeeded();
    }

    /**
     * @param PasswordPolicyStateAttribute[] $state
     */
    private function toOperationalChanges(array $state): OperationalChanges
    {
        $changes = [];

        foreach ($state as $attribute) {
            $name = $attribute->field->attributeName();
            $changes[] = $attribute->values === []
                ? Change::reset($name)
                : Change::replace($name, ...$attribute->values);
        }

        return OperationalChanges::of(...$changes);
    }
}
