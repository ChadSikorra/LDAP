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
 * Verifies a plaintext password against a stored value that may be hashed ({SHA}, {SSHA}, {MD5}, {SMD5}, {BCRYPT}, {ARGON2}).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PasswordHashVerifier
{
    public function verify(
        #[SensitiveParameter]
        string $plain,
        string $stored,
    ): bool {
        return match (true) {
            str_starts_with($stored, '{SHA}') => $this->verifySha($plain, substr($stored, 5)),
            str_starts_with($stored, '{SSHA}') => $this->verifySsha($plain, substr($stored, 6)),
            str_starts_with($stored, '{MD5}') => $this->verifyMd5($plain, substr($stored, 5)),
            str_starts_with($stored, '{SMD5}') => $this->verifySmd5($plain, substr($stored, 6)),
            str_starts_with($stored, '{BCRYPT}') => password_verify($plain, substr($stored, 8)),
            str_starts_with($stored, '{ARGON2}') => password_verify($plain, substr($stored, 8)),
            default => $plain === $stored,
        };
    }

    private function verifySha(
        #[SensitiveParameter]
        string $plain,
        string $encoded,
    ): bool {
        return base64_encode(sha1($plain, true)) === $encoded;
    }

    private function verifySsha(
        #[SensitiveParameter]
        string $plain,
        string $encoded,
    ): bool {
        $decoded = base64_decode($encoded);
        $salt = substr($decoded, 20);

        return substr($decoded, 0, 20) === sha1($plain . $salt, true);
    }

    private function verifyMd5(
        #[SensitiveParameter]
        string $plain,
        string $encoded,
    ): bool {
        return base64_encode(md5($plain, true)) === $encoded;
    }

    private function verifySmd5(
        #[SensitiveParameter]
        string $plain,
        string $encoded,
    ): bool {
        $decoded = base64_decode($encoded);
        $salt = substr($decoded, 16);

        return substr($decoded, 0, 16) === md5($plain . $salt, true);
    }
}
