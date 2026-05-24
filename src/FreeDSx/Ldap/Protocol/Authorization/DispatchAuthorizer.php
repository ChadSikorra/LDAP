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

namespace FreeDSx\Ldap\Protocol\Authorization;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordResetGate;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Resolves the identity a non-bind request runs under, applying the password-reset gate and RFC 4370 proxied authorization.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class DispatchAuthorizer
{
    public function __construct(
        private ServerAuthorization $authorizer,
        private PasswordResetGate $passwordResetGate = new PasswordResetGate(),
        private ?ProxiedAuthorizationResolver $proxiedAuthorizationResolver = null,
    ) {}

    /**
     * @throws OperationException on proxied authorization denial.
     */
    public function authorize(LdapMessageRequest $message): DispatchAuthorization
    {
        $request = $message->getRequest();

        if (!$this->authorizer->isAuthenticated() && $this->authorizer->isAuthenticationRequired($request)) {
            return DispatchAuthorization::authenticationRequired();
        }

        $token = $this->authorizer->getToken();

        if ($this->mustChangePasswordFirst($request, $token)) {
            return DispatchAuthorization::passwordChangeRequired();
        }

        $effectiveToken = $this->effectiveToken(
            $message,
            $token,
        );

        return DispatchAuthorization::proceed($effectiveToken);
    }

    /**
     * A bound identity flagged with pwdReset may only change its password or end the session (draft-behera-10 §8.1.2).
     */
    private function mustChangePasswordFirst(
        RequestInterface $request,
        TokenInterface $token,
    ): bool {
        return $token instanceof AuthenticatedTokenInterface
            && $token->mustChangePassword()
            && !$this->passwordResetGate->isPermitted($request, $token);
    }

    /**
     * @throws OperationException
     */
    private function effectiveToken(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): TokenInterface {
        if ($this->proxiedAuthorizationResolver === null) {
            return $token;
        }

        return $this->proxiedAuthorizationResolver->resolve(
            $message->getRequest(),
            $message->controls(),
            $token,
        );
    }
}
