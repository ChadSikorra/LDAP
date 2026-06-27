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
use SensitiveParameter;

/**
 * Represents a bound and authorized identity, identified by its authorization identity (authzId).
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class BindToken implements AuthenticatedTokenInterface
{
    private string $id;

    private readonly Dn $resolvedDn;

    private string $authcId;

    private string $password;

    private int $version;

    private bool $mustChangePassword = false;

    private readonly ?Dn $authorizingDn;

    /**
     * @param AuthzId $authzId the resolved authorization identity (its DN, or the username when it is not a DN)
     * @param string|null $authcId the authentication identity as presented, for auditing; defaults to the authzId value
     */
    public function __construct(
        private readonly AuthzId $authzId,
        #[SensitiveParameter]
        string $password = '',
        ?string $authcId = null,
        int $version = 3,
        ?Dn $authorizingDn = null,
    ) {
        $this->id = Uuid::v4();
        $this->resolvedDn = new Dn($authzId->getValue());
        $this->authcId = $authcId ?? $authzId->getValue();
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
            AuthzId::fromDn(new Dn($dn)),
            $password,
            $dn,
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
            AuthzId::fromDn($resolvedDn),
            '',
            $username,
            $version,
            $authorizingDn,
        );
    }

    /**
     * Creates a token for an identity that resolved to a bare username rather than a DN.
     */
    public static function fromUsername(
        string $username,
        int $version = 3,
        ?Dn $authorizingDn = null,
    ): self {
        return new self(
            AuthzId::fromUsername($username),
            '',
            $username,
            $version,
            $authorizingDn,
        );
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getAuthzId(): AuthzId
    {
        return $this->authzId;
    }

    public function getUsername(): ?string
    {
        return $this->authcId;
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
