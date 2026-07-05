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

use Swoole\Process;

use const SIGINT;
use const SIGTERM;

/**
 * Installs termination-signal handlers via the Swoole event loop for graceful shutdown.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SwooleShutdownSignals implements ShutdownSignalsInterface
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
        foreach (self::SIGNALS as $signal) {
            Process::signal(
                $signal,
                static function () use ($handler): void {
                    $handler();
                },
            );
        }
    }
}
