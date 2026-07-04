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

namespace FreeDSx\Ldap\Server\Clock;

use function usleep;

/**
 * Blocking sleeper.
 *
 * PCNTL runs per-process, so it's fine. Yields under coroutines like Swoole (via the SWOOLE_HOOK_SLEEP runtime hook).
 */
final class BlockingSleeper implements Sleeper
{
    public function sleep(float $seconds): void
    {
        if ($seconds <= 0.0) {
            return;
        }

        usleep((int) ($seconds * 1_000_000));
    }
}
