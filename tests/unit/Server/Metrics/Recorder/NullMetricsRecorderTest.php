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
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use PHPUnit\Framework\TestCase;

final class NullMetricsRecorderTest extends TestCase
{
    public function test_every_observation_is_a_harmless_no_op(): void
    {
        $this->expectNotToPerformAssertions();

        $subject = new NullMetricsRecorder();
        $subject->serverStarted(1_000);
        $subject->serverReloaded(2_000);
        $subject->connectionObserved(ConnectionObservation::Opened);
        $subject->operationObserved(new OperationObservation(
            'search',
            true,
            0.1,
            ResultCode::SUCCESS,
        ));
    }
}
