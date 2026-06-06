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
 * A unit of transport traffic.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class TrafficObservation
{
    public function __construct(
        public int $bytesSent = 0,
        public int $bytesReceived = 0,
        public int $entriesReturned = 0,
    ) {}
}
