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

namespace Tests\Unit\FreeDSx\Ldap\Server\Metrics\Rollup;

use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Metrics\Rollup\MetricsDelta;
use FreeDSx\Ldap\Server\Metrics\Rollup\MetricsDeltaMessage;
use FreeDSx\Ldap\Server\Metrics\Rollup\MetricsDeltaMessageFactory;
use FreeDSx\Ldap\Server\Metrics\Snapshot\OperationMetrics;
use FreeDSx\Ldap\Server\Metrics\Snapshot\TrafficMetrics;
use PHPUnit\Framework\TestCase;

final class MetricsDeltaMessageTest extends TestCase
{
    public function test_it_round_trips_a_delta_through_the_wire_form(): void
    {
        $delta = new MetricsDelta(
            new OperationMetrics(
                counts: ['search' => 4, 'bind' => 1],
                errors: ['search' => 1],
                durationSeconds: ['search' => 0.5],
                resultCodeCounts: [ResultCode::SUCCESS => 4],
                bindCounts: ['simple' => 1],
                searchScopeCounts: ['sub' => 4],
            ),
            new TrafficMetrics(
                bytesSent: 4096,
                bytesReceived: 256,
                entriesReturned: 4,
            ),
        );

        $message = new MetricsDeltaMessage($delta);
        $rebuilt = (new MetricsDeltaMessageFactory())->fromArray($message->toArray());

        self::assertInstanceOf(
            MetricsDeltaMessage::class,
            $rebuilt,
        );
        self::assertSame(
            $delta->operations->counts,
            $rebuilt->delta()->operations->counts,
        );
        self::assertSame(
            $delta->operations->bindCounts,
            $rebuilt->delta()->operations->bindCounts,
        );
        self::assertSame(
            $delta->operations->searchScopeCounts,
            $rebuilt->delta()->operations->searchScopeCounts,
        );
        self::assertSame(
            $delta->traffic->bytesSent,
            $rebuilt->delta()->traffic->bytesSent,
        );
        self::assertSame(
            $delta->traffic->bytesReceived,
            $rebuilt->delta()->traffic->bytesReceived,
        );
        self::assertSame(
            $delta->traffic->entriesReturned,
            $rebuilt->delta()->traffic->entriesReturned,
        );
    }
}
