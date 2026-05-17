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

namespace Tests\Unit\FreeDSx\Ldap\Server\Clock;

use FreeDSx\Ldap\Server\Clock\SystemClock;
use PHPUnit\Framework\TestCase;

final class SystemClockTest extends TestCase
{
    public function test_now_returns_utc(): void
    {
        $clock = new SystemClock();

        self::assertSame(
            'UTC',
            $clock->now()->getTimezone()->getName(),
        );
    }

    public function test_now_is_monotonically_non_decreasing(): void
    {
        $clock = new SystemClock();

        $first = $clock->now();
        $second = $clock->now();

        self::assertGreaterThanOrEqual(
            $first,
            $second,
        );
    }
}
