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

namespace FreeDSx\Ldap\Protocol\Authorization;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\InvalidArgumentException;

use function sprintf;
use function str_starts_with;
use function strlen;
use function substr;

/**
 * An authorization identity in SASL/RFC 4513 form: a typed value plus its "dn:" /"u:" / anonymous form.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class AuthzId
{
    private function __construct(
        private AuthzIdType $type,
        private string $value = '',
    ) {}

    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * Parse the "dn:" / "u:" form; an empty string is the anonymous identity.
     *
     * @throws InvalidArgumentException on an unrecognized (non-dn/u) form
     */
    public static function fromString(string $authzId): self
    {
        return match (true) {
            $authzId === '' => new self(AuthzIdType::Anonymous),
            str_starts_with($authzId, AuthzIdType::Dn->value) => new self(
                AuthzIdType::Dn,
                substr($authzId, strlen(AuthzIdType::Dn->value)),
            ),
            str_starts_with($authzId, AuthzIdType::Username->value) => new self(
                AuthzIdType::Username,
                substr($authzId, strlen(AuthzIdType::Username->value)),
            ),
            default => throw new InvalidArgumentException(sprintf(
                'The authorization identity "%s" must use the "dn:" or "u:" form.',
                $authzId,
            )),
        };
    }

    public static function anonymous(): self
    {
        return new self(AuthzIdType::Anonymous);
    }

    public static function fromDn(Dn $dn): self
    {
        return new self(
            AuthzIdType::Dn,
            $dn->toString(),
        );
    }

    public static function fromUsername(string $username): self
    {
        return new self(
            AuthzIdType::Username,
            $username,
        );
    }

    public function isType(AuthzIdType $type): bool
    {
        return $this->type === $type;
    }

    /**
     * The identity value without its form prefix (the DN string, or the username; empty when anonymous).
     */
    public function getValue(): string
    {
        return $this->value;
    }

    public function toString(): string
    {
        return $this->type->value . $this->value;
    }
}
