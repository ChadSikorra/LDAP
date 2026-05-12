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
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Sasl\Mechanism\MechanismName;
use SensitiveParameter;

/**
 * Resolves the bind name to an Entry and verifies its userPassword; supports {SHA}, {SSHA}, {MD5}, {SMD5}, and plaintext.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PasswordAuthenticator implements PasswordAuthenticatableInterface
{
    public function __construct(
        private readonly BindNameResolverInterface $resolver,
        private readonly LdapBackendInterface $backend,
        private readonly PasswordHashVerifier $hashVerifier = new PasswordHashVerifier(),
    ) {}

    public function authenticate(
        string $name,
        #[SensitiveParameter]
        string $password,
    ): AuthenticatedTokenInterface {
        $entry = $this->resolver->resolve(
            $name,
            $this->backend,
        );

        if ($entry === null) {
            $this->denyCredentials();
        }

        $attr = $entry->get('userPassword');

        if ($attr === null) {
            $this->denyCredentials();
        }

        foreach ($attr->getValues() as $stored) {
            if ($this->hashVerifier->verify($password, $stored)) {
                return new BindToken(
                    $name,
                    $password,
                    $entry->getDn(),
                );
            }
        }

        $this->denyCredentials();
    }

    public function getSaslIdentity(
        string $username,
        MechanismName $mechanism,
    ): ?SaslIdentity {
        $entry = $this->resolver->resolve(
            $username,
            $this->backend,
        );

        if ($entry === null) {
            return null;
        }

        $password = $entry->get('userPassword')?->getValues()[0];

        if ($password === null) {
            return null;
        }

        return new SaslIdentity(
            $password,
            $entry->getDn(),
        );
    }

    private function denyCredentials(): never
    {
        throw new OperationException(
            'Invalid credentials.',
            ResultCode::INVALID_CREDENTIALS,
        );
    }
}
