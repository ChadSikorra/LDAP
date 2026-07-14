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
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ForwardPasswordPolicyStateRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\SystemChange\SystemChangeWriterInterface;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Applies a replica-forwarded password-policy state: union the failure times, bound by the observed success, and
 * derive lockout on the primary.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerPasswordPolicyForwardHandler implements ServerProtocolHandlerInterface
{
    public function __construct(
        private ServerQueue $queue,
        private LdapBackendInterface $backend,
        private PasswordPolicyResolver $policyResolver,
        private PasswordPolicyEngine $engine,
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

        $changes = $this->resolveChanges($request);
        if (!$changes->isEmpty()) {
            $this->changeWriter->write(
                $request->getDn(),
                $changes,
            );
        }

        $this->queue->sendMessage(new LdapMessageResponse(
            $message->getMessageId(),
            new ExtendedResponse(new LdapResult(ResultCode::SUCCESS)),
        ));

        return OperationOutcomeResult::succeeded();
    }

    /**
     * @throws OperationException
     */
    private function resolveChanges(ForwardPasswordPolicyStateRequest $request): OperationalChanges
    {
        $entry = $this->backend->get($request->getDn());
        if ($entry === null) {
            return OperationalChanges::none();
        }

        $policy = $this->policyResolver->resolveFor($entry);
        if ($policy === null) {
            return OperationalChanges::none();
        }

        return $this->engine->recordForwardedState(
            UserPasswordState::fromEntry($entry),
            $policy,
            $request->getFailureTimes(),
            $request->getLastSuccess(),
        );
    }
}
