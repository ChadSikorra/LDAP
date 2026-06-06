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

namespace Tests\Unit\FreeDSx\Ldap\Server\Metrics\Snapshot;

use FreeDSx\Ldap\Server\Metrics\Snapshot\ConnectionMetrics;
use FreeDSx\Ldap\Server\Metrics\Snapshot\LifecycleMetrics;
use FreeDSx\Ldap\Server\Metrics\Snapshot\MetricsSnapshot;
use FreeDSx\Ldap\Server\Metrics\Snapshot\OperationMetrics;
use FreeDSx\Ldap\Server\Metrics\Snapshot\TrafficMetrics;
use PHPUnit\Framework\TestCase;

final class MetricsSnapshotTest extends TestCase
{
    private MetricsSnapshot $subject;

    protected function setUp(): void
    {
        $this->subject = new MetricsSnapshot(
            new LifecycleMetrics(
                1_000,
                2_000,
                3,
            ),
            new ConnectionMetrics(
                4,
                10,
                2,
                1,
                0,
                5,
            ),
            new OperationMetrics(
                ['search' => 7],
                ['search' => 1],
                ['search' => 3.5],
                [0 => 6, 32 => 1],
                ['simple' => 5, 'anonymous' => 2],
                ['base' => 3, 'sub' => 4],
            ),
            ['search' => 2, 'bind' => 1],
            new TrafficMetrics(
                4096,
                512,
                9,
            ),
        );
    }

    public function test_it_round_trips_through_an_array_via_json(): void
    {
        $json = json_encode($this->subject->toArray());
        self::assertIsString($json);

        $restored = MetricsSnapshot::fromArray((array) json_decode(
            $json,
            true,
        ));

        self::assertEquals(
            $this->subject,
            $restored,
        );
    }

    public function test_operation_totals_sum_across_operations(): void
    {
        self::assertSame(
            7,
            $this->subject->operations->total(),
        );
        self::assertSame(
            1,
            $this->subject->operations->totalErrors(),
        );
    }

    public function test_from_array_yields_an_empty_snapshot_for_missing_sections(): void
    {
        self::assertEquals(
            new MetricsSnapshot(),
            MetricsSnapshot::fromArray([]),
        );
    }
}
