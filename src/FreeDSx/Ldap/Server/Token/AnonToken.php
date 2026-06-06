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
use FreeDSx\Ldap\Server\Utility\Uuid;

/**
 * Represents a token for an anonymous bind.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class AnonToken implements TokenInterface
{
    private string $id;

    private ?string $username;

    private int $version;

    private readonly ?Dn $authorizingDn;

    public function __construct(
        ?string $username = null,
        int $version = 3,
        ?Dn $authorizingDn = null,
    ) {
        $this->id = Uuid::v4();
        $this->username = $username;
        $this->version = $version;
        $this->authorizingDn = $authorizingDn;
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getUsername(): ?string
    {
        return $this->username;
    }

    public function getPassword(): ?string
    {
        return null;
    }

    public function getVersion(): int
    {
        return $this->version;
    }

    public function getAuthorizingDn(): ?Dn
    {
        return $this->authorizingDn;
    }
}
