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
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\OperationType;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHasher;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashVerifier;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\PasswordPolicy\Attempt\PasswordModifyAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyChangeGuard;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles RFC 3062 Password Modify extended requests.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerPasswordModifyHandler implements ServerProtocolHandlerInterface
{
    use ServerCriticalControlTrait;

    public function __construct(
        private ServerQueue $queue,
        private LdapBackendInterface $backend,
        private WriteOperationDispatcher $writeDispatcher,
        private AccessControlInterface $accessControl,
        private BindNameResolverInterface $identityResolver,
        private EventLogger $eventLogger = new EventLogger(null),
        private PasswordHashVerifier $hashVerifier = new PasswordHashVerifier(),
        private PasswordHasher $hasher = new PasswordHasher(),
        private ResponseFactory $responseFactory = new ResponseFactory(),
        private ?PasswordPolicyChangeGuard $changeGuard = null,
        private ?PasswordPolicyContext $passwordPolicyContext = null,
    ) {}

    /**
     * {@inheritDoc}
     *
     * @throws EncoderException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): void {
        $this->passwordPolicyContext?->clear();
        $targetDn = null;

        try {
            $this->assertNoCriticalUnsupportedControls($message->controls());
            $targetDn = $this->process(
                $message,
                $token,
            );
        } catch (OperationException $e) {
            $control = $this->passwordPolicyControl();
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                $e->getCode(),
                $e->getMessage(),
                null,
                ...($control === null ? [] : [$control]),
            ));
            $this->recordFailure(
                $e,
                $token,
                $targetDn,
                $message,
            );

            return;
        }

        $this->eventLogger->record(
            ServerEvent::PasswordModifySuccess,
            [
                EventContext::TARGET => [EventContext::DN => $targetDn->toString()],
            ],
            subject: $token,
            message: $message,
        );
    }

    /**
     * @throws OperationException
     * @throws EncoderException
     */
    private function process(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): Dn {
        if (!$token instanceof AuthenticatedTokenInterface) {
            throw new OperationException(
                'Authentication required.',
                ResultCode::UNWILLING_TO_PERFORM,
            );
        }

        /** @var ExtendedRequest $raw */
        $raw = $message->getRequest();
        $request = PasswordModifyRequest::fromAsn1($raw->toAsn1());
        $entry = $this->resolveTargetEntry(
            $request,
            $token,
        );
        $targetDn = $entry->getDn();

        $this->authorizeRequest(
            $token,
            $targetDn,
        );
        $this->verifyOldPassword(
            $request,
            $entry,
        );

        $newPassword = $request->getNewPassword();
        $generated = null;

        if ($newPassword === null) {
            $generated = $this->hasher->generate();
            $newPassword = $generated;
        }

        $isSelf = $this->isSelf(
            $token,
            $targetDn,
        );
        $hashed = $this->hasher->hash($newPassword);
        $deltas = $this->changeGuard?->enforce(new PasswordModifyAttempt(
            target: $entry,
            newPassword: $newPassword,
            hashedNewPassword: $hashed,
            oldPassword: $request->getOldPassword(),
            isSelf: $isSelf,
            passwordIsCleartext: true,
        )) ?? OperationalChanges::none();

        $this->applyPasswordChange(
            $targetDn,
            $hashed,
            $deltas,
            $token,
            $message,
        );

        // A successful self-change satisfies any pwdReset requirement, so lift the session restriction immediately.
        if ($isSelf && $token instanceof BindToken) {
            $token->clearMustChangePassword();
        }

        $control = $this->passwordPolicyControl();
        $this->queue->sendMessage(new LdapMessageResponse(
            $message->getMessageId(),
            new PasswordModifyResponse(
                new LdapResult(ResultCode::SUCCESS),
                $generated,
            ),
            ...($control === null ? [] : [$control]),
        ));

        return $targetDn;
    }

    private function isSelf(
        AuthenticatedTokenInterface $token,
        Dn $targetDn,
    ): bool {
        return $token->getResolvedDn()->normalize()->toString() === $targetDn->normalize()->toString();
    }

    private function passwordPolicyControl(): ?Control
    {
        $control = $this->passwordPolicyContext?->buildResponseControl();
        $this->passwordPolicyContext?->clear();

        return $control;
    }

    private function recordFailure(
        OperationException $exception,
        TokenInterface $token,
        ?Dn $targetDn,
        LdapMessageRequest $message,
    ): void {
        $event = ServerEvent::fromOperationException(
            $exception,
            ServerEvent::AuthorizationDeniedWrite,
            ServerEvent::PasswordModifyFailed,
        );

        if ($event === null) {
            return;
        }

        $context = [];

        if ($targetDn !== null) {
            $context[EventContext::TARGET] = [EventContext::DN => $targetDn->toString()];
        }

        $this->eventLogger->recordFailure(
            $event,
            $exception,
            $context,
            subject: $token,
            message: $message,
        );
    }

    /**
     * @throws OperationException
     */
    private function resolveTargetEntry(
        PasswordModifyRequest $request,
        AuthenticatedTokenInterface $token,
    ): Entry {
        $userIdentity = $request->getUsername();

        $entry = $userIdentity === null || $userIdentity === ''
            ? $this->backend->get($token->getResolvedDn())
            : $this->identityResolver->resolve(
                $userIdentity,
                $this->backend,
            );

        if ($entry === null) {
            throw new OperationException(
                'The target entry does not exist.',
                ResultCode::NO_SUCH_OBJECT,
            );
        }

        return $entry;
    }

    /**
     * @throws OperationException
     */
    private function authorizeRequest(
        AuthenticatedTokenInterface $token,
        Dn $targetDn,
    ): void {
        $this->accessControl->authorizeOperation(
            OperationType::PasswordModify,
            $token,
            $targetDn,
        );
        $this->accessControl->authorizeAttribute(
            $token,
            $targetDn,
            'userPassword',
        );
    }

    /**
     * @throws OperationException
     */
    private function verifyOldPassword(
        PasswordModifyRequest $request,
        Entry $entry,
    ): void {
        $oldPassword = $request->getOldPassword();

        if ($oldPassword === null) {
            return;
        }

        foreach ($entry->get('userPassword')?->getValues() ?? [] as $stored) {
            if ($this->hashVerifier->verify($oldPassword, $stored)) {
                return;
            }
        }

        throw new OperationException(
            'Invalid credentials.',
            ResultCode::INVALID_CREDENTIALS,
        );
    }

    /**
     * Persists the new password plus any policy bookkeeping deltas in one command. When deltas are present the
     * command is system-flagged so the NO-USER-MODIFICATION operational attributes are accepted; ACL was already
     * checked in authorizeRequest().
     *
     * @throws OperationException
     */
    private function applyPasswordChange(
        Dn $targetDn,
        string $hashed,
        OperationalChanges $deltas,
        TokenInterface $token,
        LdapMessageRequest $message,
    ): void {
        $changes = [
            Change::replace('userPassword', $hashed),
            ...$deltas->changes,
        ];
        $context = $deltas->isEmpty()
            ? new WriteContext(
                $token,
                $message->controls(),
            )
            : WriteContext::system(
                $token,
                $message->controls(),
            );

        $this->writeDispatcher->dispatch(
            new UpdateCommand(
                $targetDn,
                $changes,
            ),
            $context,
        );
    }
}
