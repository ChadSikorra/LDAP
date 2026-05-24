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
use SensitiveParameter;

/**
 * Represents a username/password token that is bound and authorized.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class BindToken implements AuthenticatedTokenInterface
{
    private string $id;

    private string $username;

    private readonly Dn $resolvedDn;

    private string $password;

    private int $version;

    private bool $mustChangePassword = false;

    private readonly ?Dn $authorizingDn;

    public function __construct(
        string $username,
        #[SensitiveParameter]
        string $password,
        Dn $resolvedDn,
        int $version = 3,
        ?Dn $authorizingDn = null,
    ) {
        $this->id = Uuid::v4();
        $this->username = $username;
        $this->resolvedDn = $resolvedDn;
        $this->password = $password;
        $this->version = $version;
        $this->authorizingDn = $authorizingDn;
    }

    public static function fromDn(
        string $dn,
        #[SensitiveParameter]
        string $password,
        int $version = 3,
        ?Dn $authorizingDn = null,
    ): self {
        return new self(
            $dn,
            $password,
            new Dn($dn),
            $version,
            $authorizingDn,
        );
    }

    /**
     * Creates a token for a SASL-authenticated identity; no plaintext password is carried.
     */
    public static function fromSasl(
        string $username,
        Dn $resolvedDn,
        int $version = 3,
        ?Dn $authorizingDn = null,
    ): self {
        return new self(
            $username,
            '',
            $resolvedDn,
            $version,
            $authorizingDn,
        );
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
        return $this->password;
    }

    public function getResolvedDn(): Dn
    {
        return $this->resolvedDn;
    }

    public function getAuthorizingDn(): ?Dn
    {
        return $this->authorizingDn;
    }

    /**
     * Flags that the bound identity must change its password before any other operation is permitted.
     */
    public function markMustChangePassword(): void
    {
        $this->mustChangePassword = true;
    }

    /**
     * Lifts the restriction once the bound identity has changed its password within the session.
     */
    public function clearMustChangePassword(): void
    {
        $this->mustChangePassword = false;
    }

    public function mustChangePassword(): bool
    {
        return $this->mustChangePassword;
    }

    public function getVersion(): int
    {
        return $this->version;
    }
}
