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
use Psr\Log\LoggerInterface;

use function microtime;
use function pcntl_fork;
use function pcntl_waitpid;
use function posix_kill;

use const SIGTERM;
use const WNOHANG;

/**
 * Runs the retention sweep and replica daemon as forked child processes under PCNTL.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PcntlBackgroundTasks implements BackgroundTasksInterface
{
    private ?int $sweepPid = null;

    private ?int $daemonPid = null;

    private float $lastSweepAt = 0.0;

    private Closure $childStart;

    /**
     * @param ?Closure(): ?RetentionSweeper $makeSweeper builds the sweep worker in the child, or null when not journaling
     * @param ?Closure(): ?LdapReplica $makeDaemon builds the replica daemon in the child, or null when not a replica
     * @param float $sweepIntervalSeconds cadence between retention sweeps
     */
    public function __construct(
        private readonly ?Closure $makeSweeper,
        private readonly ?Closure $makeDaemon,
        private readonly float $sweepIntervalSeconds,
        private readonly ?LoggerInterface $logger = null,
    ) {
        $this->childStart = static function (): void {};
    }

    public function onChildStart(Closure $onStart): void
    {
        $this->childStart = $onStart;
    }

    public function start(): void
    {
        $this->lastSweepAt = microtime(true);

        if ($this->makeDaemon !== null) {
            $this->daemonPid = $this->fork($this->runDaemon(...));
        }
    }

    public function tick(): void
    {
        $this->reapDaemon();
        $this->maintainSweep();
    }

    public function stop(): void
    {
        $this->endChild($this->daemonPid);
        $this->daemonPid = null;
        $this->endChild($this->sweepPid);
        $this->sweepPid = null;
    }

    /**
     * On a fixed cadence, fork a short-lived child to prune the shared journal so the parent keeps accepting.
     */
    private function maintainSweep(): void
    {
        if ($this->makeSweeper === null) {
            return;
        }

        $this->reapSweep();

        if (!$this->isSweepDue()) {
            return;
        }

        $this->lastSweepAt = microtime(true);
        $this->sweepPid = $this->fork($this->runSweep(...));
    }

    private function isSweepDue(): bool
    {
        return $this->sweepPid === null
            && (microtime(true) - $this->lastSweepAt) >= $this->sweepIntervalSeconds;
    }

    private function runSweep(): void
    {
        if ($this->makeSweeper === null) {
            return;
        }

        ($this->makeSweeper)()?->sweep();
    }

    private function runDaemon(): void
    {
        if ($this->makeDaemon === null) {
            return;
        }

        ($this->makeDaemon)()?->run();
    }

    /**
     * @param Closure(): void $childBody
     */
    private function fork(Closure $childBody): ?int
    {
        $pid = pcntl_fork();

        if ($pid === -1) {
            $this->logger?->warning('Unable to fork a background task.');

            return null;
        }

        if ($pid === 0) {
            ($this->childStart)();
            $childBody();
            exit(0);
        }

        return $pid;
    }

    private function reapSweep(): void
    {
        if ($this->pidExited($this->sweepPid)) {
            $this->sweepPid = null;
        }
    }

    private function reapDaemon(): void
    {
        if ($this->daemonPid === null || !$this->pidExited($this->daemonPid)) {
            return;
        }

        $this->daemonPid = null;
        $this->logger?->warning('The replica synchronization daemon exited unexpectedly.');
    }

    private function pidExited(?int $pid): bool
    {
        if ($pid === null) {
            return false;
        }

        $status = 0;
        $result = pcntl_waitpid(
            $pid,
            $status,
            WNOHANG,
        );

        return $result === -1 || $result > 0;
    }

    private function endChild(?int $pid): void
    {
        if ($pid === null) {
            return;
        }

        posix_kill(
            $pid,
            SIGTERM,
        );
        $status = 0;
        pcntl_waitpid(
            $pid,
            $status,
        );
    }
}
