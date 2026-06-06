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

namespace FreeDSx\Ldap\Server\Metrics\Rollup;

use FreeDSx\Ldap\Server\Metrics\Snapshot\OperationMetrics;
use FreeDSx\Ldap\Server\Metrics\Snapshot\TrafficMetrics;

/**
 * The additive metrics a child process reports to the parent in one rollup flush.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class MetricsDelta
{
    public function __construct(
        public OperationMetrics $operations = new OperationMetrics(),
        public TrafficMetrics $traffic = new TrafficMetrics(),
    ) {}
}
