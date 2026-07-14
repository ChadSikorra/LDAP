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
 * A unit of background work that runs continuously until shutdown.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LongLivedTask
{
    /**
     * @param Closure(): void $run blocks until shutdown
     * @param ?Closure(): void $stop optional cooperative stop for a host that shares the task's memory.
     */
    public function __construct(
        public string $name,
        public Closure $run,
        public ?Closure $stop = null,
    ) {}
}
