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

namespace FreeDSx\Ldap\Protocol\Bind;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Bind\Sasl\SaslExchange;
use FreeDSx\Ldap\Protocol\Bind\Sasl\SaslExchangeInput;
use FreeDSx\Ldap\Protocol\Bind\Sasl\SaslExchangeResult;
use FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor\SaslUsernameExtractorFactory;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\MessageWrapper\SaslMessageWrapper;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Sasl\Challenge\ChallengeInterface;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Sasl;
use FreeDSx\Sasl\SaslInterface;

/**
 * Handles a SASL bind request on the server side.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SaslBind implements BindInterface
{
    use VersionValidatorTrait;

    /**
     * @param string[] $mechanisms
     */
    public function __construct(
        private readonly ServerQueue $queue,
        private readonly SaslExchange $exchange,
        private readonly SaslInterface $sasl = new Sasl(),
        private readonly array $mechanisms = [],
        private readonly ResponseFactory $responseFactory = new ResponseFactory(),
        private readonly SaslUsernameExtractorFactory $usernameExtractorFactory = new SaslUsernameExtractorFactory(),
    ) {}

    /**
     * {@inheritDoc}
     */
    public function supports(LdapMessageRequest $request): bool
    {
        return $request->getRequest() instanceof SaslBindRequest;
    }

    /**
     * {@inheritDoc}
     *
     * @throws OperationException
     */
    public function bind(LdapMessageRequest $message): TokenInterface
    {
        $request = $this->validateRequest($message);
        $mechNameStr = $request->getMechanism();
        $this->validateMechanism($mechNameStr);

        $mechName = MechanismName::from($mechNameStr);

        $result = $this->exchange->run(new SaslExchangeInput(
            challenge: $this->getServerChallenge($mechName),
            mechName: $mechName,
            initialMessage: $message,
            initialCredentials: $request->getCredentials(),
        ));

        return $this->finalize(
            $result,
            $mechName,
        );
    }

    /**
     * @throws RuntimeException
     * @throws OperationException
     */
    private function validateRequest(LdapMessageRequest $message): SaslBindRequest
    {
        $request = $message->getRequest();

        if (!$request instanceof SaslBindRequest) {
            throw new RuntimeException(sprintf(
                'Expected a SaslBindRequest, got: %s',
                get_class($request),
            ));
        }

        self::validateVersion($request);

        return $request;
    }

    /**
     * @throws OperationException
     */
    private function validateMechanism(string $mechName): void
    {
        if (!in_array($mechName, $this->mechanisms, true)) {
            throw new OperationException(
                sprintf('The SASL mechanism "%s" is not supported.', $mechName),
                ResultCode::AUTH_METHOD_UNSUPPORTED,
            );
        }
    }

    private function getServerChallenge(MechanismName $mechName): ChallengeInterface
    {
        return $this->sasl
            ->get($mechName)
            ->challenge(true);
    }

    /**
     * @throws OperationException
     * @throws EncoderException
     * @throws SaslException
     */
    private function finalize(
        SaslExchangeResult $result,
        MechanismName $mechName,
    ): TokenInterface {
        $context = $result->getContext();
        $message = $result->getLastMessage();

        if (!$context->isAuthenticated()) {
            // Send the failure response directly using the current $message, which reflects
            // the latest message consumed from the queue (correct ID for multi-round exchanges).
            // Without this, the outer OperationException handler would use the stale first
            // message ID and the client would receive a response with the wrong message ID.
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                ResultCode::INVALID_CREDENTIALS,
                'Invalid credentials.',
            ));

            throw new OperationException(
                'Invalid credentials.',
                ResultCode::INVALID_CREDENTIALS,
            );
        }

        try {
            $usernameCredentials = $result->getUsernameCredentials();

            if ($usernameCredentials === null) {
                throw new OperationException(
                    sprintf('Unable to extract username for mechanism "%s": no credentials were received.', $mechName->value),
                    ResultCode::PROTOCOL_ERROR,
                );
            }

            $username = $this->usernameExtractorFactory
                ->make($mechName)
                ->extractUsername(
                    $mechName,
                    $usernameCredentials,
                );

            $resolvedDn = $result->getResolvedDn();

            if ($resolvedDn === null) {
                throw new OperationException(
                    'Invalid credentials.',
                    ResultCode::INVALID_CREDENTIALS,
                );
            }
        } catch (OperationException $e) {
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                $e->getCode(),
                $e->getMessage(),
            ));

            throw $e;
        }

        // The success response must be sent before activating the security layer.
        $this->queue->sendMessage($this->responseFactory->getStandardResponse($message));

        if ($context->hasSecurityLayer()) {
            $mech = $this->sasl->get($mechName);
            $this->queue->setMessageWrapper(new SaslMessageWrapper($mech->securityLayer(), $context));
        }

        return BindToken::fromSasl(
            $username,
            $resolvedDn,
        );
    }
}
