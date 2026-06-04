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

namespace FreeDSx\Ldap\Server\Metrics\Observation;

/**
 * A single observed operation, with its low-cardinality metric dimensions.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class OperationObservation
{
    /**
     * @param string $operation The operation label (matches the audit log's operation values).
     * @param int $resultCode The LDAP result code the operation produced.
     */
    public function __construct(
        public string $operation,
        public bool $succeeded,
        public float $durationSeconds,
        public int $resultCode,
    ) {}
}
