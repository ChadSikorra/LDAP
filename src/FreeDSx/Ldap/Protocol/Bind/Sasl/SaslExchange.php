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

namespace FreeDSx\Ldap\Protocol\Bind\Sasl;

use Closure;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\MechanismOptionsBuilderFactory;
use FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor\SaslUsernameExtractorFactory;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\SaslContext;
use Throwable;

/**
 * Drives the SASL challenge-response loop on the server side.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SaslExchange
{
    public function __construct(
        private readonly ServerQueue $queue,
        private readonly ResponseFactory $responseFactory,
        private readonly MechanismOptionsBuilderFactory $optionsBuilderFactory,
        private readonly SaslUsernameExtractorFactory $usernameExtractorFactory = new SaslUsernameExtractorFactory(),
    ) {}

    /**
     * Runs the full SASL exchange until the mechanism reports completion.
     *
     * @throws OperationException if the client sends a non-SASL request mid-exchange.
     */
    public function run(SaslExchangeInput $input): SaslExchangeResult
    {
        $mechName = $input->getMechName();
        $optionsBuilder = $this->optionsBuilderFactory->make($mechName);
        $message = $input->getInitialMessage();

        /** @var Closure(?string): SaslContext $challengeProcessor */
        $challengeProcessor = fn(?string $challengeReceived): SaslContext => $input->getChallenge()->challenge(
            $challengeReceived,
            $optionsBuilder->buildOptions($challengeReceived, $mechName),
        );

        try {
            [$context, $usernameCredentials] = $this->runExchangeLoop(
                $challengeProcessor,
                $input->getInitialCredentials(),
                $message,
            );
        } catch (OperationException $e) {
            // Once $message is a continuation, the outer ServerProtocolHandler holds a stale
            // initial-bind ID. Send the error here with the correct ID before re-throwing.
            if ($message !== $input->getInitialMessage()) {
                $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                    $message,
                    $e->getCode(),
                    $e->getMessage(),
                ));
            }

            throw $e;
        }

        return new SaslExchangeResult(
            $context,
            $message,
            $optionsBuilder->getUsername() ?? $this->extractUsername(
                $usernameCredentials,
                $mechName,
            ),
            $optionsBuilder->getResolvedDn(),
            $optionsBuilder->getAuthorizingDn(),
        );
    }

    private function extractUsername(
        ?string $credentials,
        MechanismName $mechName,
    ): ?string {
        if ($credentials === null) {
            return null;
        }

        try {
            return $this->usernameExtractorFactory
                ->make($mechName)
                ->extractUsername(
                    $mechName,
                    $credentials,
                );
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Drives the challenge-response loop until the mechanism completes.
     *
     * $message is passed by reference so the caller's catch block always holds the latest message ID.
     *
     * @param Closure(?string): SaslContext $challengeProcessor
     * @return array{SaslContext, ?string} [context, usernameCredentials]
     * @throws OperationException
     */
    private function runExchangeLoop(
        Closure $challengeProcessor,
        ?string $received,
        LdapMessageRequest &$message,
    ): array {
        $context = null;
        $prevContextResponse = null;
        // PLAIN: credentials are in $received from the start; others: first non-null continuation.
        $usernameCredentials = $received;

        while (true) {
            // DIGEST-MD5 re-entry: context is already complete from the previous iteration
            // (server-final sent, client ack received) — break to preserve the authenticated context.
            if ($context !== null && $context->isComplete()) {
                break;
            }

            $advancement = $this->advanceChallenge(
                $challengeProcessor,
                $received,
                $prevContextResponse,
            );
            $context = $advancement->context;
            $prevContextResponse = $context->getResponse();
            if ($advancement->complete) {
                break;
            }

            // Send the server's message to the client: a challenge, an empty credential prompt
            // (e.g. PLAIN when credentials are absent from the initial bind), or a server-final.
            $this->sendBindInProgress(
                $message,
                $prevContextResponse,
            );

            // Update $message so the correct ID is available if an error occurs in a later step.
            $message = $this->queue->getMessage();
            $received = $this->requireSaslContinuation($message)->getCredentials();

            if ($usernameCredentials === null && $received !== null) {
                $usernameCredentials = $received;
            }
        }

        return [
            $context,
            $usernameCredentials,
        ];
    }

    /**
     * Advances the mechanism by one step and enforces all completion break conditions.
     *
     * @param Closure(?string): SaslContext $doChallenge
     */
    private function advanceChallenge(
        Closure $doChallenge,
        ?string $received,
        ?string $prevContextResponse,
    ): ChallengeAdvancement {
        $context = $doChallenge($received);
        $contextResponse = $context->getResponse();
        $responseIsNew = ($contextResponse !== $prevContextResponse);

        // Some mechanisms (e.g. CRAM-MD5) do not clear the context response after the final
        // validation step — the stale value from the previous round remains. By comparing to
        // what we sent last time we can detect this and avoid sending a spurious second round.
        if ($context->isComplete() && !$responseIsNew) {
            return new ChallengeAdvancement($context, complete: true);
        }

        // If the mechanism reports completion with a failure (e.g. SCRAM e=invalid-proof),
        // skip sending the server-final and fall through to the INVALID_CREDENTIALS path.
        // This avoids a protocol deadlock where the client throws a SaslException on
        // receiving the e= response and never sends the ack the server would wait for.
        if ($context->isComplete() && !$context->isAuthenticated()) {
            return new ChallengeAdvancement($context, complete: true);
        }

        return new ChallengeAdvancement($context, complete: false);
    }

    /**
     * Sends a SASL_BIND_IN_PROGRESS response carrying the server's challenge or server-final data.
     */
    private function sendBindInProgress(LdapMessageRequest $message, ?string $response): void
    {
        $this->queue->sendMessage(new LdapMessageResponse(
            $message->getMessageId(),
            new BindResponse(
                new LdapResult(ResultCode::SASL_BIND_IN_PROGRESS),
                $response,
            ),
        ));
    }

    /**
     * Validates that the message received mid-exchange is a SASL bind continuation.
     *
     * @throws OperationException if the client sends a non-SASL request.
     */
    private function requireSaslContinuation(LdapMessageRequest $message): SaslBindRequest
    {
        $request = $message->getRequest();

        if ($request instanceof SaslBindRequest) {
            return $request;
        }

        throw new OperationException(
            'Expected a SASL bind continuation during the exchange.',
            ResultCode::PROTOCOL_ERROR,
        );
    }
}
