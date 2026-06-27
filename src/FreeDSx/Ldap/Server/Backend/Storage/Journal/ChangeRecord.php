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

use DateTimeImmutable;

/**
 * A PendingChange stamped by the journal.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ChangeRecord
{
    public function __construct(
        public int $seq,
        public ReplicaId $origin,
        public DateTimeImmutable $createdAt,
        public PendingChange $change,
    ) {}
}
