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

namespace Tests\Unit\FreeDSx\Ldap\Server\Metrics\Recorder;

use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Metrics\Observation\OperationObservation;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Snapshot\OperationMetrics;
use PHPUnit\Framework\TestCase;

final class InMemoryMetricsRecorderTest extends TestCase
{
    private InMemoryMetricsRecorder $subject;

    protected function setUp(): void
    {
        $this->subject = new InMemoryMetricsRecorder();
    }

    public function test_it_records_operations_with_counts_errors_and_durations(): void
    {
        $this->subject->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.5,
            ResultCode::SUCCESS,
        ));
        $this->subject->operationObserved(new OperationObservation(
            OperationType::Search,
            false,
            0.25,
            ResultCode::NO_SUCH_OBJECT,
        ));

        $operations = $this->subject->snapshot()->operations;

        self::assertSame(
            ['search' => 2],
            $operations->counts,
        );
        self::assertSame(
            ['search' => 1],
            $operations->errors,
        );
        self::assertSame(
            ['search' => 0.75],
            $operations->durationSeconds,
        );
        self::assertSame(
            [
                ResultCode::SUCCESS => 1,
                ResultCode::NO_SUCH_OBJECT => 1,
            ],
            $operations->resultCodeCounts,
        );
    }

    public function test_it_records_bind_method_and_search_scope_breakdowns(): void
    {
        $this->subject->operationObserved(new OperationObservation(
            OperationType::Bind,
            true,
            0.1,
            ResultCode::SUCCESS,
            bindMethod: 'anonymous',
        ));
        $this->subject->operationObserved(new OperationObservation(
            OperationType::Bind,
            true,
            0.1,
            ResultCode::SUCCESS,
            bindMethod: 'simple',
        ));
        $this->subject->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.1,
            ResultCode::SUCCESS,
            searchScope: 'sub',
        ));

        $operations = $this->subject->snapshot()->operations;

        self::assertSame(
            ['anonymous' => 1, 'simple' => 1],
            $operations->bindCounts,
        );
        self::assertSame(
            ['sub' => 1],
            $operations->searchScopeCounts,
        );
    }

    public function test_the_active_connection_gauge_rises_on_open_and_falls_on_close(): void
    {
        $this->subject->connectionObserved(ConnectionObservation::Opened);
        $this->subject->connectionObserved(ConnectionObservation::Opened);
        $this->subject->connectionObserved(ConnectionObservation::Closed);

        $connections = $this->subject->snapshot()->connections;

        self::assertSame(
            1,
            $connections->active,
        );
        self::assertSame(
            2,
            $connections->total,
        );
    }

    public function test_closing_more_than_were_opened_floors_the_gauge_at_zero(): void
    {
        $this->subject->connectionObserved(ConnectionObservation::Closed);

        self::assertSame(
            0,
            $this->subject->snapshot()->connections->active,
        );
    }

    public function test_it_counts_rejected_and_timed_out_connections(): void
    {
        $this->subject->connectionObserved(ConnectionObservation::Rejected);
        $this->subject->connectionObserved(ConnectionObservation::WriteTimeout);
        $this->subject->connectionObserved(ConnectionObservation::WriteTimeout);
        $this->subject->connectionObserved(ConnectionObservation::IdleTimeout);

        $connections = $this->subject->snapshot()->connections;

        self::assertSame(
            1,
            $connections->rejected,
        );
        self::assertSame(
            2,
            $connections->writeTimeouts,
        );
        self::assertSame(
            1,
            $connections->idleTimeouts,
        );
    }

    public function test_taking_the_operation_delta_returns_the_metrics_and_resets_them(): void
    {
        $this->subject->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.5,
            ResultCode::SUCCESS,
        ));

        $delta = $this->subject->takeOperationDelta();

        self::assertSame(
            ['search' => 1],
            $delta->counts,
        );
        self::assertSame(
            [ResultCode::SUCCESS => 1],
            $delta->resultCodeCounts,
        );
        self::assertSame(
            [],
            $this->subject->takeOperationDelta()->counts,
        );
    }

    public function test_resetting_operations_clears_the_accumulators_but_keeps_connections(): void
    {
        $this->subject->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.5,
            ResultCode::SUCCESS,
        ));
        $this->subject->connectionObserved(ConnectionObservation::Opened);

        $this->subject->resetOperations();

        $snapshot = $this->subject->snapshot();
        self::assertSame(
            [],
            $snapshot->operations->counts,
        );
        self::assertSame(
            1,
            $snapshot->connections->active,
        );
    }

    public function test_merging_an_operation_delta_sums_into_the_totals(): void
    {
        $this->subject->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.5,
            ResultCode::SUCCESS,
        ));

        $this->subject->mergeOperations(new OperationMetrics(
            counts: ['search' => 2, 'bind' => 1],
            errors: ['search' => 1],
            durationSeconds: ['search' => 0.25],
            resultCodeCounts: [ResultCode::SUCCESS => 2],
            bindCounts: ['anonymous' => 1],
            searchScopeCounts: ['sub' => 2],
        ));

        $operations = $this->subject->snapshot()->operations;

        self::assertSame(
            ['search' => 3, 'bind' => 1],
            $operations->counts,
        );
        self::assertSame(
            ['search' => 1],
            $operations->errors,
        );
        self::assertSame(
            ['search' => 0.75],
            $operations->durationSeconds,
        );
        self::assertSame(
            [ResultCode::SUCCESS => 3],
            $operations->resultCodeCounts,
        );
        self::assertSame(
            ['anonymous' => 1],
            $operations->bindCounts,
        );
        self::assertSame(
            ['sub' => 2],
            $operations->searchScopeCounts,
        );
    }

    public function test_it_records_the_start_time_and_counts_reloads(): void
    {
        $this->subject->serverStarted(1_000);
        $this->subject->serverReloaded(2_000);
        $this->subject->serverReloaded(3_000);

        $lifecycle = $this->subject->snapshot()->lifecycle;

        self::assertSame(
            1_000,
            $lifecycle->startedAt,
        );
        self::assertSame(
            3_000,
            $lifecycle->lastReloadAt,
        );
        self::assertSame(
            2,
            $lifecycle->reloadCount,
        );
    }
}
