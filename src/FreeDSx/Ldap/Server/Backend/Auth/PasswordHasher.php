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

namespace FreeDSx\Ldap\Server\Backend\Auth;

use SensitiveParameter;

/**
 * Hashes plaintext passwords into the format understood by {@see PasswordHashVerifier}.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PasswordHasher
{
    public function __construct(
        private PasswordHashScheme $scheme = PasswordHashScheme::Bcrypt,
    ) {}

    /**
     * Hash a plaintext password using the configured scheme.
     */
    public function hash(
        #[SensitiveParameter]
        string $plain,
    ): string {
        return match ($this->scheme) {
            PasswordHashScheme::Ssha => $this->hashSsha($plain),
            PasswordHashScheme::Bcrypt => $this->hashWithPhpAlgo(
                $plain,
                PASSWORD_BCRYPT,
                PasswordHashScheme::Bcrypt,
            ),
            PasswordHashScheme::Argon2 => $this->hashWithPhpAlgo(
                $plain,
                PASSWORD_ARGON2ID,
                PasswordHashScheme::Argon2,
            ),
        };
    }

    /**
     * Generate a cryptographically random 16-character password.
     */
    public function generate(): string
    {
        return bin2hex(random_bytes(8));
    }

    private function hashSsha(
        #[SensitiveParameter]
        string $plain,
    ): string {
        $salt = random_bytes(8);

        return PasswordHashScheme::Ssha->value
            . base64_encode(sha1($plain . $salt, true) . $salt);
    }

    private function hashWithPhpAlgo(
        #[SensitiveParameter]
        string $plain,
        string $algo,
        PasswordHashScheme $scheme,
    ): string {
        $hash = password_hash(
            $plain,
            $algo,
        );

        return $scheme->value . $hash;
    }
}
