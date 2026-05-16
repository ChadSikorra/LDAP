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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support;

use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support\SortKeyComparator;
use PHPUnit\Framework\TestCase;

final class SortKeyComparatorTest extends TestCase
{
    private SortKeyComparator $subject;

    protected function setUp(): void
    {
        $this->subject = new SortKeyComparator();
    }

    private function entry(
        string $dn,
        string ...$cnValues,
    ): Entry {
        return new Entry(
            new Dn($dn),
            new Attribute('cn', ...$cnValues),
        );
    }

    /**
     * @param list<Entry> $sorted
     * @return list<string>
     */
    private function cnValues(array $sorted): array
    {
        return array_map(
            static fn(Entry $e): string => $e->get('cn')?->getValues()[0] ?? '',
            $sorted,
        );
    }

    public function test_sort_ascending_by_single_key(): void
    {
        $alice = $this->entry('cn=Alice,dc=example,dc=com', 'Alice');
        $bob = $this->entry('cn=Bob,dc=example,dc=com', 'Bob');
        $charlie = $this->entry('cn=Charlie,dc=example,dc=com', 'Charlie');

        $sorted = $this->subject->sort(
            [$charlie, $alice, $bob],
            [SortKey::ascending('cn')],
        );

        self::assertSame(
            ['Alice', 'Bob', 'Charlie'],
            $this->cnValues($sorted),
        );
    }

    public function test_sort_descending_by_single_key(): void
    {
        $alice = $this->entry('cn=Alice,dc=example,dc=com', 'Alice');
        $bob = $this->entry('cn=Bob,dc=example,dc=com', 'Bob');
        $charlie = $this->entry('cn=Charlie,dc=example,dc=com', 'Charlie');

        $sorted = $this->subject->sort(
            [$alice, $charlie, $bob],
            [SortKey::descending('cn')],
        );

        self::assertSame(
            ['Charlie', 'Bob', 'Alice'],
            $this->cnValues($sorted),
        );
    }

    public function test_sort_is_case_insensitive(): void
    {
        $lower = $this->entry('cn=alpha,dc=example,dc=com', 'alpha');
        $upper = $this->entry('cn=BETA,dc=example,dc=com', 'BETA');

        $sorted = $this->subject->sort(
            [$upper, $lower],
            [SortKey::ascending('cn')],
        );

        self::assertSame(
            ['alpha', 'BETA'],
            $this->cnValues($sorted),
        );
    }

    public function test_multi_valued_attribute_sorts_by_minimum_value(): void
    {
        $aEntry = new Entry(
            new Dn('cn=A,dc=example,dc=com'),
            new Attribute('cn', 'Zebra', 'Apple'),
        );
        $bEntry = new Entry(
            new Dn('cn=B,dc=example,dc=com'),
            new Attribute('cn', 'Mango'),
        );

        $sorted = $this->subject->sort(
            [$bEntry, $aEntry],
            [SortKey::ascending('cn')],
        );

        self::assertSame(
            $aEntry,
            $sorted[0],
            'Entry whose minimum value (Apple) is less than Mango should sort first',
        );
    }

    public function test_entries_missing_attribute_sort_last_for_ascending(): void
    {
        $alice = $this->entry('cn=Alice,dc=example,dc=com', 'Alice');
        $noAttr = new Entry(new Dn('cn=NoAttr,dc=example,dc=com'));

        $sorted = $this->subject->sort(
            [$noAttr, $alice],
            [SortKey::ascending('cn')],
        );

        self::assertSame(
            'Alice',
            $sorted[0]->get('cn')?->getValues()[0],
        );
        self::assertNull($sorted[1]->get('cn'));
    }

    public function test_entries_missing_attribute_sort_last_for_descending(): void
    {
        $alice = $this->entry('cn=Alice,dc=example,dc=com', 'Alice');
        $noAttr = new Entry(new Dn('cn=NoAttr,dc=example,dc=com'));

        $sorted = $this->subject->sort(
            [$noAttr, $alice],
            [SortKey::descending('cn')],
        );

        self::assertSame(
            'Alice',
            $sorted[0]->get('cn')?->getValues()[0],
        );
        self::assertNull($sorted[1]->get('cn'));
    }

    public function test_sort_cascades_through_multiple_keys(): void
    {
        $alice1 = new Entry(
            new Dn('uid=a1,dc=example,dc=com'),
            new Attribute('sn', 'Smith'),
            new Attribute('cn', 'Alice'),
        );
        $alice2 = new Entry(
            new Dn('uid=a2,dc=example,dc=com'),
            new Attribute('sn', 'Smith'),
            new Attribute('cn', 'Alice2'),
        );
        $bob = new Entry(
            new Dn('uid=b,dc=example,dc=com'),
            new Attribute('sn', 'Jones'),
            new Attribute('cn', 'Bob'),
        );

        $sorted = $this->subject->sort(
            [$alice2, $bob, $alice1],
            [SortKey::ascending('sn'), SortKey::ascending('cn')],
        );

        self::assertSame(
            'Bob',
            $sorted[0]->get('cn')?->getValues()[0],
        );
        self::assertSame(
            'Alice',
            $sorted[1]->get('cn')?->getValues()[0],
        );
        self::assertSame(
            'Alice2',
            $sorted[2]->get('cn')?->getValues()[0],
        );
    }

    public function test_sort_does_not_modify_original_array(): void
    {
        $alice = $this->entry('cn=Alice,dc=example,dc=com', 'Alice');
        $bob = $this->entry('cn=Bob,dc=example,dc=com', 'Bob');
        $original = [$bob, $alice];

        $this->subject->sort(
            $original,
            [SortKey::ascending('cn')],
        );

        self::assertSame(
            $bob,
            $original[0],
        );
    }
}
