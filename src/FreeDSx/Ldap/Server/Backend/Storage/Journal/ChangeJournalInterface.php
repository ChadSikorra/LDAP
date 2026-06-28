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

use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;

/**
 * Append-only log of committed writes.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ChangeJournalInterface
{
    /**
     * Append a change, allocating the next monotonic seq, and return the stamped record.
     */
    public function append(PendingChange $change): ChangeRecord;

    /**
     * Records with seq greater than $afterSeq, in ascending seq order.
     *
     * @api
     *
     * @return iterable<ChangeRecord>
     */
    public function read(int $afterSeq = 0): iterable;

    /**
     * Highest allocated seq, or 0 when nothing has been appended.
     *
     * @api
     */
    public function latestSeq(): int;

    /**
     * Drop records that fall outside the policy; returns how many were removed. seq keeps climbing.
     *
     * @api
     */
    public function prune(RetentionPolicy $policy): int;

    /**
     * The replica that authored this journal's records; the origin a sync cookie is stamped with.
     *
     * @api
     */
    public function origin(): ReplicaId;
}
