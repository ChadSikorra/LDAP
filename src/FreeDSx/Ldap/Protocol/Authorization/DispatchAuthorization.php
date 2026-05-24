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

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Outcome of {@see DispatchAuthorizer::authorize()}: proceed under a token, or which rejection the dispatcher must send.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class DispatchAuthorization
{
    private function __construct(
        private ?TokenInterface $token,
        private bool $authenticationRequired,
        private bool $passwordChangeRequired,
    ) {}

    public static function proceed(TokenInterface $token): self
    {
        return new self(
            $token,
            false,
            false,
        );
    }

    public static function authenticationRequired(): self
    {
        return new self(
            null,
            true,
            false,
        );
    }

    public static function passwordChangeRequired(): self
    {
        return new self(
            null,
            false,
            true,
        );
    }

    public function requiresAuthentication(): bool
    {
        return $this->authenticationRequired;
    }

    public function requiresPasswordChange(): bool
    {
        return $this->passwordChangeRequired;
    }

    /**
     * The identity the operation runs under; only valid when the request may proceed.
     *
     * @throws RuntimeException when the request was not authorized to proceed.
     */
    public function token(): TokenInterface
    {
        if ($this->token === null) {
            throw new RuntimeException('No effective token is available; the request was not authorized to proceed.');
        }

        return $this->token;
    }
}
