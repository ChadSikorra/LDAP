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

use DateTimeImmutable;

use function intdiv;
use function sprintf;

/**
 * Converts a point in time to and from an epoch-microseconds integer.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class EpochMicroseconds
{
    private const MICROS_PER_SECOND = 1_000_000;

    public static function fromDateTime(DateTimeImmutable $at): int
    {
        return (int) $at->format('Uu');
    }

    public static function toDateTime(int $micros): DateTimeImmutable
    {
        $at = DateTimeImmutable::createFromFormat(
            'U.u',
            sprintf(
                '%d.%06d',
                intdiv($micros, self::MICROS_PER_SECOND),
                $micros % self::MICROS_PER_SECOND,
            ),
        );

        // The value is always our own encoded integer, so the parse cannot realistically fail.
        return $at !== false
            ? $at
            : (new DateTimeImmutable())->setTimestamp(intdiv(
                $micros,
                self::MICROS_PER_SECOND,
            ));
    }

    public static function fromSeconds(int $seconds): int
    {
        return $seconds * self::MICROS_PER_SECOND;
    }
}
