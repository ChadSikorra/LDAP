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

namespace FreeDSx\Ldap\Server\Process\BackgroundTask;

use Closure;

/**
 * A unit of background work to run on a fixed cadence.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PeriodicTask
{
    /**
     * @param Closure(): void $run one iteration of the task
     */
    public function __construct(
        public string $name,
        public float $intervalSeconds,
        public Closure $run,
    ) {}
}
