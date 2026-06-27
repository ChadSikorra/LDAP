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
 * Token for server-internal writes, recorded as cn=system rather than any bound user.
 *
 * @api
 */
final readonly class SystemToken implements TokenInterface
{
    public const IDENTITY = 'cn=system';

    private string $id;

    private AuthzId $authzId;

    public function __construct(private int $version = 3)
    {
        $this->id = Uuid::v4();
        $this->authzId = AuthzId::fromDn(new Dn(self::IDENTITY));
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getUsername(): string
    {
        return self::IDENTITY;
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
}
