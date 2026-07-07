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

use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;

/**
 * Test sleeper that records every requested duration instead of pausing.
 */
final class RecordingSleeper implements SleeperInterface
{
    /**
     * @var list<float>
     */
    public array $durations = [];

    public function sleep(float $seconds): void
    {
        $this->durations[] = $seconds;
    }
}
