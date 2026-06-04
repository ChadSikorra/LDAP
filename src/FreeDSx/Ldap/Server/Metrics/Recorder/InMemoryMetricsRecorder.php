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

namespace FreeDSx\Ldap\Server\Metrics\Recorder;

use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\MetricsSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\Observation\OperationObservation;
use FreeDSx\Ldap\Server\Metrics\Snapshot\ConnectionMetrics;
use FreeDSx\Ldap\Server\Metrics\Snapshot\LifecycleMetrics;
use FreeDSx\Ldap\Server\Metrics\Snapshot\MetricsSnapshot;
use FreeDSx\Ldap\Server\Metrics\Snapshot\OperationMetrics;

use function max;

/**
 * Accumulates metrics in process memory and serves them as a snapshot.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class InMemoryMetricsRecorder implements MetricsRecorderInterface, MetricsSnapshotProvider
{
    private int $startedAt = 0;

    private int $lastReloadAt = 0;

    /**
     * @var int<0, max>
     */
    private int $reloadCount = 0;

    /**
     * @var int<0, max>
     */
    private int $activeConnections = 0;

    /**
     * @var int<0, max>
     */
    private int $totalConnections = 0;

    /**
     * @var int<0, max>
     */
    private int $rejectedConnections = 0;

    /**
     * @var int<0, max>
     */
    private int $writeTimeouts = 0;

    /**
     * @var int<0, max>
     */
    private int $idleTimeouts = 0;

    /**
     * @var array<string, int<0, max>>
     */
    private array $operationCounts = [];

    /**
     * @var array<string, int<0, max>>
     */
    private array $operationErrors = [];

    /**
     * @var array<string, float>
     */
    private array $operationDurationSeconds = [];

    /**
     * @var array<int, int<0, max>>
     */
    private array $resultCodeCounts = [];

    public function operationObserved(OperationObservation $observation): void
    {
        $operation = $observation->operation->value;
        $this->operationCounts[$operation] = ($this->operationCounts[$operation] ?? 0) + 1;
        $this->operationDurationSeconds[$operation] = ($this->operationDurationSeconds[$operation] ?? 0.0)
            + $observation->durationSeconds;
        $this->resultCodeCounts[$observation->resultCode] = ($this->resultCodeCounts[$observation->resultCode] ?? 0) + 1;

        if (!$observation->succeeded) {
            $this->operationErrors[$operation] = ($this->operationErrors[$operation] ?? 0) + 1;
        }
    }

    public function connectionObserved(ConnectionObservation $observation): void
    {
        match ($observation) {
            ConnectionObservation::Opened => $this->onOpened(),
            ConnectionObservation::Closed => $this->activeConnections = max(0, $this->activeConnections - 1),
            ConnectionObservation::Rejected => $this->rejectedConnections++,
            ConnectionObservation::WriteTimeout => $this->writeTimeouts++,
            ConnectionObservation::IdleTimeout => $this->idleTimeouts++,
        };
    }

    public function serverStarted(int $startedAt): void
    {
        $this->startedAt = $startedAt;
    }

    public function serverReloaded(int $reloadedAt): void
    {
        $this->lastReloadAt = $reloadedAt;
        $this->reloadCount++;
    }

    public function snapshot(): MetricsSnapshot
    {
        return new MetricsSnapshot(
            new LifecycleMetrics(
                $this->startedAt,
                $this->lastReloadAt,
                $this->reloadCount,
            ),
            new ConnectionMetrics(
                $this->activeConnections,
                $this->totalConnections,
                $this->rejectedConnections,
                $this->writeTimeouts,
                $this->idleTimeouts,
            ),
            new OperationMetrics(
                $this->operationCounts,
                $this->operationErrors,
                $this->operationDurationSeconds,
                $this->resultCodeCounts,
            ),
        );
    }

    private function onOpened(): void
    {
        $this->activeConnections++;
        $this->totalConnections++;
    }
}
