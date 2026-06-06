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

use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\Observation\OperationObservation;

/**
 * The default recorder; discards every observation for zero overhead when metrics are unconfigured.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class NullMetricsRecorder implements MetricsRecorderInterface
{
    public function operationObserved(OperationObservation $observation): void {}

    public function operationStarted(OperationType $operation): void {}

    public function connectionObserved(ConnectionObservation $observation): void {}

    public function serverStarted(int $startedAt): void {}

    public function serverReloaded(int $reloadedAt): void {}
}
