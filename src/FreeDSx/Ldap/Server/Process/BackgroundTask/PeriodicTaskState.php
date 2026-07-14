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

/**
 * Mutable runtime scheduling state for one forked periodic task.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PeriodicTaskState
{
    public ?int $pid = null;

    public function __construct(public float $lastRunAt) {}
}
