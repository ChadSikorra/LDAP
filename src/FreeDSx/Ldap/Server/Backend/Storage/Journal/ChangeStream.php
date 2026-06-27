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

/**
 * Read-only view over the journal: the seam the audit sink and RFC 4533 provider consume.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ChangeStream
{
    public function __construct(
        private ChangeJournalInterface $journal,
    ) {}

    /**
     * Records with seq greater than $afterSeq, optionally narrowed to a scope, in ascending seq order.
     *
     * @api
     *
     * @return iterable<ChangeRecord>
     */
    public function since(
        int $afterSeq = 0,
        ?ChangeScope $scope = null,
    ): iterable {
        foreach ($this->journal->read($afterSeq) as $record) {
            if ($scope === null || $scope->contains($record->change->dn)) {
                yield $record;
            }
        }
    }

    /**
     * The highest seq currently in the journal; the high-water mark a consumer cookie advances to.
     *
     * @api
     */
    public function latestSeq(): int
    {
        return $this->journal->latestSeq();
    }
}
