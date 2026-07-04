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
 * Bounds journal growth: a record is purge-eligible once it fails either limit (whichever is tighter).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class RetentionPolicy
{
    /**
     * @param ?int $maxRecords hard ceiling on retained records, or null for no count limit
     * @param ?int $maxAgeSeconds age horizon in seconds, or null for no time limit
     */
    public function __construct(
        public ?int $maxRecords = null,
        public ?int $maxAgeSeconds = null,
    ) {
        if ($maxRecords !== null && $maxRecords < 1) {
            throw new InvalidArgumentException('maxRecords must be at least 1 when set.');
        }

        if ($maxAgeSeconds !== null && $maxAgeSeconds < 1) {
            throw new InvalidArgumentException('maxAgeSeconds must be at least 1 when set.');
        }
    }

    /**
     * Whether any limit is set.
     */
    public function hasLimits(): bool
    {
        return $this->maxRecords !== null || $this->maxAgeSeconds !== null;
    }
}
