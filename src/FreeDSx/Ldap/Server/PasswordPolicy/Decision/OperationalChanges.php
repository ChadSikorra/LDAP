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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Decision;

use FreeDSx\Ldap\Entry\Change;

/**
 * Bookkeeping deltas emitted by {@see PasswordPolicyEngine} "record" methods.
 */
final readonly class OperationalChanges
{
    /**
     * @param list<Change> $changes
     */
    public function __construct(public array $changes = []) {}

    public static function none(): self
    {
        return new self();
    }

    public static function of(Change ...$changes): self
    {
        return new self(array_values($changes));
    }

    public function isEmpty(): bool
    {
        return $this->changes === [];
    }
}
