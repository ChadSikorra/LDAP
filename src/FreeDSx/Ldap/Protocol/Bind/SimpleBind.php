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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles a simple bind request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SimpleBind implements BindInterface
{
    use VersionValidatorTrait;

    public function __construct(
        private readonly ServerQueue $queue,
        private readonly PasswordAuthenticatableInterface $authenticator,
        private readonly EventLogger $eventLogger = new EventLogger(null),
        private readonly ResponseFactory $responseFactory = new ResponseFactory(),
        private readonly ?PasswordPolicyContext $passwordPolicyContext = null,
    ) {}

    /**
     * {@inheritDoc}
     */
    public function bind(LdapMessageRequest $message): TokenInterface
    {
        /** @var BindRequest $request */
        $request = $message->getRequest();
        if (!$request instanceof SimpleBindRequest) {
            throw new RuntimeException(sprintf(
                'Expected a SimpleBindRequest, got: %s',
                get_class($request),
            ));
        }

        self::validateVersion($request);

        try {
            $token = $this->simpleBind($request);
        } catch (OperationException $e) {
            $this->eventLogger->recordFailure(
                ServerEvent::BindFailure,
                $e,
                [
                    EventContext::MECHANISM => 'simple',
                    EventContext::VERSION => $request->getVersion(),
                ],
                subject: [EventContext::USERNAME => $request->getUsername()],
                message: $message,
            );

            throw $e;
        }

        $control = $this->passwordPolicyControl();
        $this->queue->sendMessage($this->responseFactory->getStandardResponse(
            $message,
            ResultCode::SUCCESS,
            '',
            null,
            ...($control === null ? [] : [$control]),
        ));
        $this->eventLogger->record(
            ServerEvent::BindSuccess,
            [
                EventContext::MECHANISM => 'simple',
                EventContext::VERSION => $request->getVersion(),
            ],
            subject: $token,
            message: $message,
        );

        return $token;
    }

    private function simpleBind(SimpleBindRequest $request): TokenInterface
    {
        return $this->authenticator->authenticate(
            $request->getUsername(),
            $request->getPassword(),
        );
    }

    private function passwordPolicyControl(): ?Control
    {
        $control = $this->passwordPolicyContext?->buildResponseControl();
        $this->passwordPolicyContext?->clear();

        return $control;
    }

    /**
     * @inheritDoc
     */
    public function supports(LdapMessageRequest $request): bool
    {
        return $request->getRequest() instanceof SimpleBindRequest;
    }
}
