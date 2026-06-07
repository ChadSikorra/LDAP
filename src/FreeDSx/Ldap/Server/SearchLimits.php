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

namespace FreeDSx\Ldap\Server;

/**
 * Groups the server-side search limit caps. Zero on any field means no server-side limit.
 */
final readonly class SearchLimits
{
    public function __construct(
        public int $maxSearchSize = 0,
        public int $maxSearchTimeLimit = 0,
        public int $maxSearchPageSize = 0,
        public int $maxSearchLookthrough = 0,
        public int $maxSearchPagedLookthrough = 0,
    ) {}

    /**
     * Effective lookthrough for paged searches: the paged limit when set, otherwise the regular lookthrough.
     */
    public function effectivePagedLookthrough(): int
    {
        return $this->maxSearchPagedLookthrough > 0
            ? $this->maxSearchPagedLookthrough
            : $this->maxSearchLookthrough;
    }
}
