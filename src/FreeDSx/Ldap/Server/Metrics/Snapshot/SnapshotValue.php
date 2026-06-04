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

namespace FreeDSx\Ldap\Server\Metrics\Snapshot;

use function is_array;
use function is_numeric;

/**
 * Coerces values decoded from an untyped snapshot array into the metric scalar types.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SnapshotValue
{
    public static function toInt(mixed $value): int
    {
        return is_numeric($value)
            ? (int) $value
            : 0;
    }

    /**
     * @return array<string, int>
     */
    public static function toIntMap(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        $result = [];
        foreach ($value as $key => $count) {
            $result[(string) $key] = self::toInt($count);
        }

        return $result;
    }

    /**
     * @return array<string, float>
     */
    public static function toFloatMap(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        $result = [];
        foreach ($value as $key => $duration) {
            $result[(string) $key] = is_numeric($duration)
                ? (float) $duration
                : 0.0;
        }

        return $result;
    }

    /**
     * @return array<int, int>
     */
    public static function toIntKeyedIntMap(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        $result = [];
        foreach ($value as $key => $count) {
            $result[(int) $key] = self::toInt($count);
        }

        return $result;
    }
}
