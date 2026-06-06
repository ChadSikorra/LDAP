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

namespace FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Auth\SaslIdentity;

/**
 * Shared logic for resolving and storing a SASL identity within a mechanism options builder.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait RequireIdentityTrait
{
    private ?Dn $resolvedDn = null;

    public function getResolvedDn(): ?Dn
    {
        return $this->resolvedDn;
    }

    /**
     * Validates the identity, stores its resolved DN, and returns it.
     *
     * @throws OperationException if the identity is null (user not found or not allowed).
     */
    private function requireIdentity(?SaslIdentity $identity): SaslIdentity
    {
        if ($identity === null) {
            throw new OperationException(
                'Invalid credentials.',
                ResultCode::INVALID_CREDENTIALS,
            );
        }

        $this->resolvedDn = $identity->resolvedDn;

        return $identity;
    }
}
