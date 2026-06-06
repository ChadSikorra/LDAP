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

/**
 * Moves additive metrics between a child and the parent's authoritative totals.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface MetricsRollupInterface
{
    /**
     * Return the additive metrics accumulated since the last call and reset them to zero.
     */
    public function takeDelta(): MetricsDelta;

    /**
     * Clear the additive accumulators without reporting them.
     */
    public function resetDelta(): void;

    /**
     * Fold a delta reported by a child process into the totals.
     */
    public function mergeDelta(MetricsDelta $delta): void;
}
