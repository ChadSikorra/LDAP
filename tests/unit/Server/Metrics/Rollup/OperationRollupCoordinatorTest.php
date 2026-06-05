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

use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Metrics\Observation\OperationObservation;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Rollup\OperationRollupCoordinator;
use PHPUnit\Framework\TestCase;

final class OperationRollupCoordinatorTest extends TestCase
{
    private InMemoryMetricsRecorder $childRecorder;

    private InMemoryMetricsRecorder $parentRecorder;

    private OperationRollupCoordinator $child;

    private OperationRollupCoordinator $parent;

    protected function setUp(): void
    {
        $this->childRecorder = new InMemoryMetricsRecorder();
        $this->parentRecorder = new InMemoryMetricsRecorder();
        $this->child = new OperationRollupCoordinator($this->childRecorder);
        $this->parent = new OperationRollupCoordinator($this->parentRecorder);
    }

    public function test_a_flushed_delta_is_collected_into_the_parent(): void
    {
        $channel = $this->child->openChannel();
        $this->child->enterChild($channel);

        $this->childRecorder->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.5,
            ResultCode::SUCCESS,
        ));
        $this->child->flush();
        $this->parent->collect($channel);

        self::assertSame(
            ['search' => 1],
            $this->parentRecorder->snapshot()->operations->counts,
        );
    }

    public function test_incremental_flushes_accumulate_in_the_parent(): void
    {
        $channel = $this->child->openChannel();
        $this->child->enterChild($channel);

        for ($i = 0; $i < 3; $i++) {
            $this->childRecorder->operationObserved(new OperationObservation(
                OperationType::Search,
                true,
                0.1,
                ResultCode::SUCCESS,
            ));
            $this->child->flush();
            $this->parent->collect($channel);
        }

        self::assertSame(
            ['search' => 3],
            $this->parentRecorder->snapshot()->operations->counts,
        );
    }

    public function test_entering_a_child_clears_operations_inherited_from_the_parent(): void
    {
        $channel = $this->child->openChannel();

        $this->childRecorder->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.5,
            ResultCode::SUCCESS,
        ));
        $this->child->enterChild($channel);
        $this->child->flush();
        $this->parent->collect($channel);

        self::assertSame(
            [],
            $this->parentRecorder->snapshot()->operations->counts,
        );
    }

    public function test_finishing_flushes_remaining_operations_and_signals_eof(): void
    {
        $channel = $this->child->openChannel();
        $this->child->enterChild($channel);

        $this->childRecorder->operationObserved(new OperationObservation(
            OperationType::Bind,
            true,
            0.1,
            ResultCode::SUCCESS,
        ));
        $this->child->finish();
        $this->parent->collect($channel);

        self::assertSame(
            ['bind' => 1],
            $this->parentRecorder->snapshot()->operations->counts,
        );
        self::assertSame(
            [],
            $channel->receive(),
        );
    }
}
