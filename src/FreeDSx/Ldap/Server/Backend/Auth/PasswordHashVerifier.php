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

use FreeDSx\Ldap\Exception\RuntimeException;
use SensitiveParameter;

/**
 * Verifies a plaintext password against a stored value that may be hashed ({SHA}, {SSHA}, {MD5}, {SMD5}, {BCRYPT}, {ARGON2}).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PasswordHashVerifier
{
    /**
     * Read-only legacy prefixes recognized in addition to the writable {@see PasswordHashScheme} set.
     *
     * @var list<string>
     */
    private const LEGACY_READ_PREFIXES = [
        '{SHA}',
        '{MD5}',
        '{SMD5}',
    ];

    /**
     * Whether a value begins with a recognized hash scheme, and so is not cleartext we can inspect.
     */
    public static function isHashed(string $value): bool
    {
        foreach (self::recognizedPrefixes() as $prefix) {
            if (str_starts_with($value, $prefix)) {
                return true;
            }
        }

        return false;
    }

    public function verify(
        #[SensitiveParameter]
        string $plain,
        string $stored,
    ): bool {
        foreach (self::recognizedPrefixes() as $prefix) {
            if (str_starts_with($stored, $prefix)) {
                return $this->verifyScheme(
                    $prefix,
                    $plain,
                    substr($stored, strlen($prefix)),
                );
            }
        }

        return $plain === $stored;
    }

    /**
     * Prefixes the verifier recognizes: every writable scheme plus the legacy read-only ones.
     *
     * @return list<string>
     */
    private static function recognizedPrefixes(): array
    {
        return [
            ...array_map(
                static fn(PasswordHashScheme $scheme): string => $scheme->value,
                PasswordHashScheme::cases(),
            ),
            ...self::LEGACY_READ_PREFIXES,
        ];
    }

    private function verifyScheme(
        string $prefix,
        #[SensitiveParameter]
        string $plain,
        string $encoded,
    ): bool {
        return match ($prefix) {
            PasswordHashScheme::Ssha->value => $this->verifySsha($plain, $encoded),
            PasswordHashScheme::Bcrypt->value, PasswordHashScheme::Argon2->value => password_verify($plain, $encoded),
            '{SHA}' => $this->verifySha($plain, $encoded),
            '{MD5}' => $this->verifyMd5($plain, $encoded),
            '{SMD5}' => $this->verifySmd5($plain, $encoded),
            default => throw new RuntimeException(sprintf(
                'No verification is implemented for the recognized hash scheme "%s".',
                $prefix,
            )),
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
