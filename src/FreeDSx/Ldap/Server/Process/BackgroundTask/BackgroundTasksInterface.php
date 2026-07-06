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
 * Manages a runner's background maintenance tasks (the journal retention sweep and the replica sync daemon).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface BackgroundTasksInterface
{
    /**
     * Register a hook run when a child task starts. Do implementation specific cleanup / preparation here.
     *
     * @param Closure(): void $onStart
     */
    public function onChildStart(Closure $onStart): void;

    /**
     * Launch the background tasks once the server is ready to accept connections.
     */
    public function start(): void;

    /**
     * Periodic upkeep driven from the accept loop: reap finished workers and re-launch interval tasks.
     */
    public function tick(): void;

    /**
     * Stop and reap all background tasks during shutdown.
     */
    public function stop(): void;
}
