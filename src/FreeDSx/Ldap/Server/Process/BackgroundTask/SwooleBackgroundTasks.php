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
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionSweeper;
use FreeDSx\Ldap\Sync\Consumer\LdapReplica;
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;

/**
 * Runs the retention sweep and replica daemon as background coroutines under Swoole.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SwooleBackgroundTasks implements BackgroundTasksInterface
{
    private bool $stopping = false;

    /**
     * @var ?Channel<bool>
     */
    private ?Channel $sweepWakeup = null;

    public function __construct(
        private readonly ?RetentionSweeper $sweeper = null,
        private readonly ?LdapReplica $daemon = null,
    ) {}

    public function onChildStart(Closure $onStart): void
    {
        // Coroutine workers share the parent's memory; there is nothing to release.
    }

    public function start(): void
    {
        $this->startSweep();
        $this->startDaemon();
    }

    public function tick(): void
    {
        // Coroutines are self-managing; there is nothing to reap between accepts.
    }

    public function stop(): void
    {
        $this->stopping = true;
        $this->sweepWakeup?->push(true);
        $this->daemon?->stop();
    }

    private function startSweep(): void
    {
        if ($this->sweeper === null) {
            return;
        }

        $sweeper = $this->sweeper;
        $wakeup = $this->sweepWakeup = new Channel(1);

        Coroutine::create(function () use ($sweeper, $wakeup): void {
            while (!$this->stopping) {
                // pop() returns the pushed value on shutdown, or false after the interval elapses.
                if ($wakeup->pop(RetentionSweeper::DEFAULT_INTERVAL_SECONDS) !== false) {
                    break;
                }

                $sweeper->sweep();
            }
        });
    }

    private function startDaemon(): void
    {
        if ($this->daemon === null) {
            return;
        }

        $daemon = $this->daemon;

        Coroutine::create(static function () use ($daemon): void {
            $daemon->run();
        });
    }
}
