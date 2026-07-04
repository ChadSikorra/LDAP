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

namespace Tests\Support\FreeDSx\Ldap\Server\Clock;

use Closure;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use RuntimeException;

/**
 * Test sleeper that runs an optional callback each tick and caps iterations so a runaway loop fails fast.
 */
final class CallbackSleeper implements SleeperInterface
{
    private int $ticks = 0;

    public function __construct(
        private readonly ?Closure $onSleep = null,
        private readonly int $maxTicks = 20,
    ) {}

    public function sleep(float $seconds): void
    {
        if (++$this->ticks > $this->maxTicks) {
            throw new RuntimeException('The loop did not terminate within the expected number of iterations.');
        }

        if ($this->onSleep !== null) {
            ($this->onSleep)();
        }
    }
}
