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

namespace FreeDSx\Ldap\Server\Token;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;

/**
 * Represents a generic authentication token.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface TokenInterface
{
    public function getId(): string;

    public function getUsername(): ?string;

    /**
     * The effective authorization identity.
     */
    public function getAuthzId(): AuthzId;

    public function getVersion(): int;

    /**
     * The bound identity that proxied this one (RFC 4370), for audit; null when the operation is not proxied.
     */
    public function getAuthorizingDn(): ?Dn;
}
