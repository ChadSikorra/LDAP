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
 * Hashes plaintext passwords into the SSHA format understood by {@see PasswordHashVerifier}.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PasswordHasher
{
    /**
     * Hash a plaintext password using salted SHA-1 (SSHA), compatible with OpenLDAP defaults.
     */
    public function hash(
        #[SensitiveParameter]
        string $plain,
    ): string {
        $salt = random_bytes(8);

        return '{SSHA}' . base64_encode(sha1($plain . $salt, true) . $salt);
    }

    /**
     * Generate a cryptographically random 16-character password.
     */
    public function generate(): string
    {
        return bin2hex(random_bytes(8));
    }
}
