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
use FreeDSx\Ldap\Server\Utility\Uuid;

/**
 * The configured manager super-user: an authenticated, privileged identity never subject to must-change.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ManagerToken implements AuthenticatedTokenInterface, PrivilegedTokenInterface
{
    private string $id;

    private AuthzId $authzId;

    public function __construct(
        private Dn $dn,
        private int $version = 3,
    ) {
        $this->id = Uuid::v4();
        $this->authzId = AuthzId::fromDn($dn);
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getUsername(): string
    {
        return $this->dn->toString();
    }

    public function getAuthzId(): AuthzId
    {
        return $this->authzId;
    }

    public function getVersion(): int
    {
        return $this->version;
    }

    public function getAuthorizingDn(): ?Dn
    {
        return null;
    }

    public function getResolvedDn(): Dn
    {
        return $this->dn;
    }

    public function mustChangePassword(): bool
    {
        return false;
    }

    public function markMustChangePassword(): void {}

    public function clearMustChangePassword(): void {}
}
