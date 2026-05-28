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

namespace Tests\Unit\FreeDSx\Ldap\Ldif;

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Ldif\LdifOutputOptions;
use FreeDSx\Ldap\Ldif\LdifParser;
use FreeDSx\Ldap\Ldif\LdifWriter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class LdifWriterTest extends TestCase
{
    public function test_it_writes_an_entry_with_a_version_header(): void
    {
        $ldif = (new LdifWriter())->write([
            Entry::create('cn=foo,dc=x', ['cn' => 'foo', 'sn' => 'Bar']),
        ]);

        self::assertStringStartsWith("version: 1\n\ndn: cn=foo,dc=x\n", $ldif);
        self::assertStringContainsString("\ncn: foo\n", $ldif);
        self::assertStringContainsString("\nsn: Bar\n", $ldif);
    }

    public function test_it_omits_the_version_header_when_disabled(): void
    {
        $ldif = (new LdifWriter((new LdifOutputOptions())->setIncludeVersion(false)))->write([
            Entry::create('cn=foo,dc=x', ['cn' => 'foo']),
        ]);

        self::assertStringStartsWith('dn: cn=foo,dc=x', $ldif);
    }

    #[DataProvider('unsafeValues')]
    public function test_it_base64_encodes_values_that_are_not_safe_strings(string $value): void
    {
        $ldif = (new LdifWriter((new LdifOutputOptions())->setIncludeVersion(false)))->write([
            Entry::create('cn=foo,dc=x', ['cn' => $value]),
        ]);

        self::assertStringContainsString('cn:: ' . base64_encode($value), $ldif);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function unsafeValues(): array
    {
        return [
            'leading space' => [' leading'],
            'trailing space' => ['trailing '],
            'leading colon' => [':colon'],
            'leading less-than' => ['<value'],
            'non-ascii' => ['Bär'],
            'embedded newline' => ["line1\nline2"],
        ];
    }

    public function test_it_writes_a_safe_value_in_plain_form(): void
    {
        $ldif = (new LdifWriter((new LdifOutputOptions())->setIncludeVersion(false)))->write([
            Entry::create('cn=foo,dc=x', ['cn' => 'plainValue']),
        ]);

        self::assertStringContainsString("cn: plainValue\n", $ldif);
    }

    public function test_it_folds_lines_longer_than_the_max_length(): void
    {
        $options = (new LdifOutputOptions())
            ->setIncludeVersion(false)
            ->setMaxLineLength(20);
        $ldif = (new LdifWriter($options))->write([
            Entry::create('cn=foo,dc=x', ['description' => str_repeat('a', 60)]),
        ]);

        self::assertStringContainsString("\n ", $ldif);
        foreach (explode("\n", $ldif) as $line) {
            self::assertLessThanOrEqual(20, strlen($line));
        }
    }

    public function test_it_round_trips_with_the_parser(): void
    {
        $entries = new Entries(
            Entry::create('cn=foo,dc=example,dc=com', [
                'objectClass' => ['top', 'person'],
                'cn' => 'foo',
                'sn' => ['Bär', ' spaced '],
            ]),
            Entry::create('cn=baz,dc=example,dc=com', [
                'cn' => 'baz',
                'description' => str_repeat('x', 200),
            ]),
        );

        $ldif = (new LdifWriter())->write($entries);
        $parsed = (new LdifParser())->parse($ldif);

        self::assertSame(
            $this->normalize($entries),
            $this->normalize($parsed),
        );
    }

    /**
     * @return array<string, array<string, string[]>>
     */
    private function normalize(Entries $entries): array
    {
        $out = [];

        foreach ($entries->toArray() as $entry) {
            $attributes = [];
            foreach ($entry->getAttributes() as $attribute) {
                $attributes[$attribute->getDescription()] = $attribute->getValues();
            }
            $out[$entry->getDn()->toString()] = $attributes;
        }

        return $out;
    }
}
