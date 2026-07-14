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

use FreeDSx\Ldap\Entry\Dn;

/**
 * A subject's replica-local password-policy state plus its forward watermark (current vs last-forwarded sequence).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ReplicaForwardState
{
    public function __construct(
        public Dn $dn,
        public ReplicaPasswordState $state,
        public int $sequence,
        public int $forwarded = 0,
    ) {}

    public static function initial(Dn $dn): self
    {
        return new self(
            $dn,
            ReplicaPasswordState::empty(),
            0,
        );
    }

    /**
     * Whether the state has advanced past the last-forwarded watermark and is awaiting forward.
     */
    public function isPending(): bool
    {
        return $this->sequence > $this->forwarded;
    }

    /**
     * Whether the forwarded watermark may advance to $sequence: it is newer than the last forward, but not newer than
     * the state actually recorded.
     */
    public function canAdvanceTo(int $sequence): bool
    {
        return $sequence > $this->forwarded && $sequence <= $this->sequence;
    }

    public function advancedTo(int $sequence): self
    {
        return new self(
            $this->dn,
            $this->state,
            $this->sequence,
            $sequence,
        );
    }

    public function applied(ReplicaPasswordState $state): self
    {
        return new self(
            $this->dn,
            $state,
            $this->sequence + 1,
            $this->forwarded,
        );
    }
}
