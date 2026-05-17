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

/**
 * Output scheme used by {@see PasswordHasher} when hashing a new password.
 */
enum PasswordHashScheme: string
{
    case Ssha = '{SSHA}';
    case Bcrypt = '{BCRYPT}';
    case Argon2 = '{ARGON2}';
}
