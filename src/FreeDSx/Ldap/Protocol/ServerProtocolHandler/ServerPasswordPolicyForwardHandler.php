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

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ForwardPasswordPolicyStateRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use FreeDSx\Ldap\Server\Token\SystemToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Applies a replica-forwarded password-policy state: atomically union the failure times, bound by the observed
 * success, and derive lockout on the primary under an exclusive entry lock.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerPasswordPolicyForwardHandler implements ServerProtocolHandlerInterface
{
    public function __construct(
        private WritableLdapBackendInterface $backend,
        private PasswordPolicyResolver $policyResolver,
        private PasswordPolicyEngine $engine,
    ) {}

    /**
     * {@inheritDoc}
     *
     * @throws OperationException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): ResponseStream {
        $request = $message->getRequest();
        if (!$request instanceof ForwardPasswordPolicyStateRequest) {
            throw new OperationException(
                'The password policy forward request is malformed.',
                ResultCode::PROTOCOL_ERROR,
            );
        }

        $this->apply($request);

        return ResponseStream::reply(
            $message,
            OperationOutcomeResult::succeeded(),
            new ExtendedResponse(new LdapResult(ResultCode::SUCCESS)),
        );
    }

    /**
     * @throws OperationException
     */
    private function apply(ForwardPasswordPolicyStateRequest $request): void
    {
        $this->backend->atomicUpdate(
            $request->getDn(),
            WriteContext::system(
                new SystemToken(),
                new ControlBag(),
            ),
            function (Entry $entry) use ($request): array {
                $policy = $this->policyResolver->resolveFor($entry);

                if ($policy === null) {
                    return [];
                }

                return $this->engine->recordForwardedState(
                    UserPasswordState::fromEntry($entry),
                    $policy,
                    $request->getFailureTimes(),
                    $request->getLastSuccess(),
                )->changes;
            },
        );
    }
}
