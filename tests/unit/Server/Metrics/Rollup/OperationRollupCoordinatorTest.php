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

    public function test_a_child_delta_is_reported_and_collected_into_the_parent(): void
    {
        $channel = $this->child->openChannel();

        $this->childRecorder->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.5,
            ResultCode::SUCCESS,
        ));

        $this->child->reportChild($channel);
        $this->parent->collect($channel);

        self::assertSame(
            ['search' => 1],
            $this->parentRecorder->snapshot()->operations->counts,
        );
    }

    public function test_starting_a_child_clears_inherited_operations_before_it_reports(): void
    {
        $channel = $this->child->openChannel();

        $this->childRecorder->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.5,
            ResultCode::SUCCESS,
        ));
        $this->child->startChild();
        $this->child->reportChild($channel);
        $this->parent->collect($channel);

        self::assertSame(
            [],
            $this->parentRecorder->snapshot()->operations->counts,
        );
    }
}
