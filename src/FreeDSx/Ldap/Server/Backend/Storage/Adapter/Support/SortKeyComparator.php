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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support;

use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Entry\Entry;

/**
 * Sorts a list of entries in-place by an ordered list of SortKeys.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SortKeyComparator
{
    /**
     * Returns a new sorted array.
     *
     * @param list<Entry> $entries
     * @param SortKey[] $sortKeys
     * @return list<Entry>
     */
    public function sort(
        array $entries,
        array $sortKeys,
    ): array {
        usort(
            $entries,
            fn(Entry $a, Entry $b): int => $this->compare(
                $a,
                $b,
                $sortKeys,
            ),
        );

        return $entries;
    }

    /**
     * @param SortKey[] $sortKeys
     */
    private function compare(
        Entry $a,
        Entry $b,
        array $sortKeys,
    ): int {
        foreach ($sortKeys as $sortKey) {
            $result = $this->compareByKey(
                $a,
                $b,
                $sortKey,
            );

            if ($result !== 0) {
                return $result;
            }
        }

        return 0;
    }

    private function compareByKey(
        Entry $a,
        Entry $b,
        SortKey $sortKey,
    ): int {
        $cmp = $this->rawCompare(
            $this->minValue(
                $a,
                $sortKey->getAttribute(),
            ),
            $this->minValue(
                $b,
                $sortKey->getAttribute(),
            ),
        );

        return $sortKey->getUseReverseOrder() ? -$cmp : $cmp;
    }

    /**
     * Compares two values treating NULL (a missing attribute) as the largest value, per RFC 2891 §2.2.
     */
    private function rawCompare(
        ?string $aValue,
        ?string $bValue,
    ): int {
        if ($aValue === null && $bValue === null) {
            return 0;
        }

        if ($aValue === null) {
            return 1;
        }

        if ($bValue === null) {
            return -1;
        }

        return strcasecmp(
            $aValue,
            $bValue,
        );
    }

    /**
     * Returns the case-insensitive minimum value, consistent with the SQL backend's MIN(value_lower).
     * Null when the attribute is absent or empty.
     */
    private function minValue(
        Entry $entry,
        string $attribute,
    ): ?string {
        $attr = $entry->get($attribute);

        if ($attr === null) {
            return null;
        }

        $values = $attr->getValues();

        if ($values === []) {
            return null;
        }

        return array_reduce(
            $values,
            self::caseInsensitiveMin(...),
        );
    }

    private static function caseInsensitiveMin(
        ?string $min,
        string $value,
    ): string {
        return $min === null || strcasecmp($value, $min) < 0
            ? $value
            : $min;
    }
}
