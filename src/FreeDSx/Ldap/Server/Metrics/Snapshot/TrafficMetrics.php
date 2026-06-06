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

namespace FreeDSx\Ldap\Server\Metrics\Snapshot;

/**
 * Transport-level traffic totals.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class TrafficMetrics
{
    public function __construct(
        public int $bytesSent = 0,
        public int $bytesReceived = 0,
        public int $entriesReturned = 0,
    ) {}

    /**
     * @return array<string, int>
     */
    public function toArray(): array
    {
        return [
            'bytes_sent' => $this->bytesSent,
            'bytes_received' => $this->bytesReceived,
            'entries_returned' => $this->entriesReturned,
        ];
    }

    /**
     * @param array<array-key, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            bytesSent: SnapshotValue::toInt($data['bytes_sent'] ?? null),
            bytesReceived: SnapshotValue::toInt($data['bytes_received'] ?? null),
            entriesReturned: SnapshotValue::toInt($data['entries_returned'] ?? null),
        );
    }
}
