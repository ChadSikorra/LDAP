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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Replica;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;

/**
 * Replica-owned volatile password-policy attributes for one subject, held locally.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ReplicaPasswordState
{
    /**
     * @var array<string, Attribute> keyed by lowercased attribute name
     */
    private array $attributes;

    /**
     * @param list<Attribute> $attributes
     */
    public function __construct(array $attributes = [])
    {
        $keyed = [];

        foreach ($attributes as $attribute) {
            $keyed[strtolower($attribute->getName())] = $attribute;
        }

        $this->attributes = $keyed;
    }

    public static function empty(): self
    {
        return new self();
    }

    public function isEmpty(): bool
    {
        return $this->attributes === [];
    }

    /**
     * Apply engine-emitted operational deltas (replace / reset) and return the resulting state.
     */
    public function withChanges(OperationalChanges $changes): self
    {
        $attributes = $this->attributes;

        foreach ($changes->changes as $change) {
            $attribute = $change->getAttribute();
            $key = strtolower($attribute->getName());

            if ($change->isReset() || $attribute->getValues() === []) {
                unset($attributes[$key]);

                continue;
            }

            $attributes[$key] = $attribute;
        }

        return new self(array_values($attributes));
    }

    /**
     * Project this local state onto a partial entry so the shared UserPasswordState parser can read it.
     */
    public function toUserPasswordState(Dn $dn): UserPasswordState
    {
        return UserPasswordState::fromEntry(Entry::raw(
            $dn,
            array_values($this->attributes),
        ));
    }
}
