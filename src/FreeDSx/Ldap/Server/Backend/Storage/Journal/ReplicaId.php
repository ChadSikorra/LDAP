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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal;

use FreeDSx\Ldap\Exception\InvalidArgumentException;

/**
 * Identity of the replica that authored a change.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ReplicaId
{
    public function __construct(
        private string $value,
    ) {
        if ($this->value === '') {
            throw new InvalidArgumentException('A replica id cannot be empty.');
        }
    }

    public function __toString(): string
    {
        return $this->value;
    }

    /**
     * The default single-master identity.
     */
    public static function local(): self
    {
        return new self('local');
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }
}
