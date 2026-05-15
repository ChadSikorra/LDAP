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
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
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
        private PasswordHashVerifier $hashVerifier = new PasswordHashVerifier(),
        private PasswordHasher $hasher = new PasswordHasher(),
        private ResponseFactory $responseFactory = new ResponseFactory(),
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
        try {
            $this->assertNoCriticalUnsupportedControls($message->controls());
            $this->process(
                $message,
                $token,
            );
        } catch (OperationException $e) {
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                $e->getCode(),
                $e->getMessage(),
            ));
        }
    }

    /**
     * @throws OperationException
     * @throws EncoderException
     */
    private function process(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): void {
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

        $this->applyPasswordChange(
            $targetDn,
            $this->hasher->hash($newPassword),
            $token,
            $message,
        );

        $this->queue->sendMessage(new LdapMessageResponse(
            $message->getMessageId(),
            new PasswordModifyResponse(
                new LdapResult(ResultCode::SUCCESS),
                $generated,
            ),
        ));
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
     * @throws OperationException
     */
    private function applyPasswordChange(
        Dn $targetDn,
        string $hashed,
        TokenInterface $token,
        LdapMessageRequest $message,
    ): void {
        $this->writeDispatcher->dispatch(
            new UpdateCommand(
                $targetDn,
                [Change::replace('userPassword', $hashed)],
            ),
            new WriteContext(
                $token,
                $message->controls(),
            ),
        );
    }
}
