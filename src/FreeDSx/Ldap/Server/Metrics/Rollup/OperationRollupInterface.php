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

/**
 * Moves operation metrics between a child and the parent's authoritative totals.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface OperationRollupInterface
{
    /**
     * Return the operation metrics accumulated since the last call and reset them to zero.
     */
    public function takeOperationDelta(): OperationMetrics;

    /**
     * Clear the operation accumulators.
     */
    public function resetOperations(): void;

    /**
     * Fold an operation-metrics delta reported by a child process into the totals.
     */
    public function mergeOperations(OperationMetrics $delta): void;
}
