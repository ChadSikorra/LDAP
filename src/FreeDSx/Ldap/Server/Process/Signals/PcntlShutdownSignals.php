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

namespace FreeDSx\Ldap\Server\Process\Signals;

use function pcntl_async_signals;
use function pcntl_signal;

use const SIGINT;
use const SIGTERM;

/**
 * Installs POSIX termination-signal handlers via ext-pcntl for graceful shutdown.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PcntlShutdownSignals implements ShutdownSignalsInterface
{
    /**
     * @var list<int>
     */
    private const SIGNALS = [
        SIGINT,
        SIGTERM,
    ];

    public function onShutdown(callable $handler): void
    {
        pcntl_async_signals(true);

        foreach (self::SIGNALS as $signal) {
            pcntl_signal(
                $signal,
                static function () use ($handler): void {
                    $handler();
                },
            );
        }
    }
}
