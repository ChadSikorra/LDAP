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

namespace FreeDSx\Ldap\Server\Metrics;

use FreeDSx\Ldap\Server\Metrics\Snapshot\MetricsSnapshot;

/**
 * Supplies a point-in-time metrics snapshot, e.g. for the cn=monitor entry.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface MetricsSnapshotProvider
{
    public function snapshot(): MetricsSnapshot;
}
