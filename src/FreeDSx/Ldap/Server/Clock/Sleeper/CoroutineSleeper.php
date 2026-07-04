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

namespace FreeDSx\Ldap\Server\Clock\Sleeper;

use Swoole\Coroutine;

/**
 * Yields the current coroutine for a swoole safe sleeper.
 */
final class CoroutineSleeper implements SleeperInterface
{
    public function sleep(float $seconds): void
    {
        if ($seconds <= 0.0) {
            return;
        }

        Coroutine::sleep($seconds);
    }
}
