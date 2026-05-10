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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Sasl\Mechanism\MechanismName;
use SensitiveParameter;

/**
 * Implemented by anything that can handle bind authentication.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PasswordAuthenticatableInterface
{
    /**
     * Authenticate $name with $password and return a token representing the bound identity.
     *
     * @throws OperationException on invalid credentials or unresolvable bind name
     */
    public function authenticate(
        string $name,
        #[SensitiveParameter]
        string $password,
    ): AuthenticatedTokenInterface;

    /**
     * Return the plaintext password for $username (SCRAM/CRAM derive keys from plaintext), or null to reject the bind.
     *
     * RFC 5803 pre-computed StoredKey/ServerKey is not supported.
     */
    public function getPassword(
        string $username,
        MechanismName $mechanism,
    ): ?string;
}
