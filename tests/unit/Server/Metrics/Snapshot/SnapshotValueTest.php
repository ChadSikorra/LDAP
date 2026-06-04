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

namespace Tests\Unit\FreeDSx\Ldap\Server\Metrics\Snapshot;

use FreeDSx\Ldap\Server\Metrics\Snapshot\SnapshotValue;
use PHPUnit\Framework\TestCase;

final class SnapshotValueTest extends TestCase
{
    public function test_to_int_coerces_numeric_values_and_defaults_others_to_zero(): void
    {
        self::assertSame(
            5,
            SnapshotValue::toInt(5),
        );
        self::assertSame(
            5,
            SnapshotValue::toInt('5'),
        );
        self::assertSame(
            5,
            SnapshotValue::toInt(5.9),
        );
        self::assertSame(
            0,
            SnapshotValue::toInt('not-a-number'),
        );
        self::assertSame(
            0,
            SnapshotValue::toInt(null),
        );
        self::assertSame(
            0,
            SnapshotValue::toInt(['array']),
        );
    }

    public function test_to_int_map_coerces_values_and_defaults_corrupt_entries_to_zero(): void
    {
        self::assertSame(
            ['search' => 3, 'bind' => 0],
            SnapshotValue::toIntMap([
                'search' => '3',
                'bind' => 'corrupt',
            ]),
        );
    }

    public function test_to_float_map_coerces_values(): void
    {
        self::assertSame(
            ['search' => 1.5, 'bind' => 0.0],
            SnapshotValue::toFloatMap([
                'search' => '1.5',
                'bind' => null,
            ]),
        );
    }

    public function test_to_int_keyed_int_map_casts_keys_to_int(): void
    {
        self::assertSame(
            [0 => 6, 32 => 1],
            SnapshotValue::toIntKeyedIntMap([
                '0' => '6',
                '32' => 1,
            ]),
        );
    }

    public function test_non_array_values_yield_an_empty_map(): void
    {
        self::assertSame(
            [],
            SnapshotValue::toIntMap('nope'),
        );
        self::assertSame(
            [],
            SnapshotValue::toFloatMap(null),
        );
        self::assertSame(
            [],
            SnapshotValue::toIntKeyedIntMap(42),
        );
    }
}
