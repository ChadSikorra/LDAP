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
use FreeDSx\Ldap\Server\Metrics\Rollup\OperationDeltaMessage;
use FreeDSx\Ldap\Server\Metrics\Rollup\OperationDeltaMessageFactory;
use FreeDSx\Ldap\Server\Metrics\Snapshot\OperationMetrics;
use PHPUnit\Framework\TestCase;

final class OperationDeltaMessageTest extends TestCase
{
    public function test_it_round_trips_operation_metrics_through_the_wire_form(): void
    {
        $operations = new OperationMetrics(
            counts: ['search' => 4, 'bind' => 1],
            errors: ['search' => 1],
            durationSeconds: ['search' => 0.5],
            resultCodeCounts: [ResultCode::SUCCESS => 4],
        );

        $message = new OperationDeltaMessage($operations);
        $rebuilt = (new OperationDeltaMessageFactory())->fromArray($message->toArray());

        self::assertInstanceOf(
            OperationDeltaMessage::class,
            $rebuilt,
        );
        self::assertSame(
            $operations->counts,
            $rebuilt->operations()->counts,
        );
        self::assertSame(
            $operations->errors,
            $rebuilt->operations()->errors,
        );
        self::assertSame(
            $operations->durationSeconds,
            $rebuilt->operations()->durationSeconds,
        );
        self::assertSame(
            $operations->resultCodeCounts,
            $rebuilt->operations()->resultCodeCounts,
        );
    }
}
