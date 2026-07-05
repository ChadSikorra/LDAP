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

/**
 * Installs termination-signal handling so a long-running process can shut down gracefully.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ShutdownSignalsInterface
{
    /**
     * Register a handler invoked when a termination signal (SIGINT/SIGTERM) is received.
     */
    public function onShutdown(callable $handler): void;
}
