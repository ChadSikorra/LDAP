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
 * Server lifecycle metrics: start time and configuration reloads.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LifecycleMetrics
{
    /**
     * @param int $startedAt Server start time (Unix timestamp), or 0 when unknown.
     * @param int $lastReloadAt Last config reload (Unix timestamp), or 0 when never reloaded.
     */
    public function __construct(
        public int $startedAt = 0,
        public int $lastReloadAt = 0,
        public int $reloadCount = 0,
    ) {}

    /**
     * @return array<string, int>
     */
    public function toArray(): array
    {
        return [
            'started_at' => $this->startedAt,
            'last_reload_at' => $this->lastReloadAt,
            'reload_count' => $this->reloadCount,
        ];
    }

    /**
     * @param array<array-key, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            startedAt: SnapshotValue::toInt($data['started_at'] ?? null),
            lastReloadAt: SnapshotValue::toInt($data['last_reload_at'] ?? null),
            reloadCount: SnapshotValue::toInt($data['reload_count'] ?? null),
        );
    }
}
