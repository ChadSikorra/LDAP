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

use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Metrics\Observation\OperationObservation;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Recorder\MetricsRecorderChain;
use PHPUnit\Framework\TestCase;

final class MetricsRecorderChainTest extends TestCase
{
    private InMemoryMetricsRecorder $first;

    private InMemoryMetricsRecorder $second;

    private MetricsRecorderChain $subject;

    protected function setUp(): void
    {
        $this->first = new InMemoryMetricsRecorder();
        $this->second = new InMemoryMetricsRecorder();
        $this->subject = new MetricsRecorderChain(
            $this->first,
            $this->second,
        );
    }

    public function test_it_fans_every_observation_out_to_each_recorder(): void
    {
        $this->subject->serverStarted(1_000);
        $this->subject->connectionObserved(ConnectionObservation::Opened);
        $this->subject->operationObserved(new OperationObservation(
            'bind',
            true,
            0.1,
            ResultCode::SUCCESS,
        ));

        foreach ([$this->first, $this->second] as $recorder) {
            $snapshot = $recorder->snapshot();
            self::assertSame(
                1_000,
                $snapshot->lifecycle->startedAt,
            );
            self::assertSame(
                1,
                $snapshot->connections->active,
            );
            self::assertSame(
                ['bind' => 1],
                $snapshot->operations->counts,
            );
        }
    }
}
