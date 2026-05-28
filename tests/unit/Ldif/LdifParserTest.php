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

use FreeDSx\Ldap\Exception\LdifParseException;
use FreeDSx\Ldap\Ldif\LdifParser;
use PHPUnit\Framework\TestCase;

final class LdifParserTest extends TestCase
{
    private LdifParser $subject;

    protected function setUp(): void
    {
        $this->subject = new LdifParser();
    }

    public function test_it_parses_a_single_entry_with_multi_valued_attributes(): void
    {
        $entries = $this->subject->parse(
            "dn: cn=foo,dc=example,dc=com\nobjectClass: top\nobjectClass: person\ncn: foo\nsn: Bar\n",
        );

        self::assertCount(1, $entries);
        $entry = $entries->toArray()[0];
        self::assertSame('cn=foo,dc=example,dc=com', $entry->getDn()->toString());
        self::assertSame(
            ['top', 'person'],
            $entry->get('objectClass')?->getValues(),
        );
        self::assertSame(['Bar'], $entry->get('sn')?->getValues());
    }

    public function test_it_parses_multiple_entries_separated_by_blank_lines(): void
    {
        $entries = $this->subject->parse(
            "dn: cn=a,dc=x\ncn: a\n\ndn: cn=b,dc=x\ncn: b\n",
        );

        self::assertCount(2, $entries);
    }

    public function test_it_unfolds_continued_lines(): void
    {
        $entry = $this->subject->parse(
            "dn: cn=foo,dc=x\ndescription: this is a long\n  description value\n",
        )->toArray()[0];

        self::assertSame(
            ['this is a long description value'],
            $entry->get('description')?->getValues(),
        );
    }

    public function test_it_decodes_a_base64_value(): void
    {
        $entry = $this->subject->parse(
            "dn: cn=foo,dc=x\ncn:: " . base64_encode('Bär') . "\n",
        )->toArray()[0];

        self::assertSame(['Bär'], $entry->get('cn')?->getValues());
    }

    public function test_it_decodes_a_base64_dn(): void
    {
        $entry = $this->subject->parse(
            "dn:: " . base64_encode('cn=Bär,dc=x') . "\ncn: x\n",
        )->toArray()[0];

        self::assertSame('cn=Bär,dc=x', $entry->getDn()->toString());
    }

    public function test_it_skips_comments_including_folded_ones(): void
    {
        $entries = $this->subject->parse(
            "# a top comment\ndn: cn=foo,dc=x\n# inline comment\n# folded\n more comment\ncn: foo\n",
        );

        self::assertCount(1, $entries);
        self::assertSame(['foo'], $entries->toArray()[0]->get('cn')?->getValues());
    }

    public function test_it_accepts_a_version_one_header(): void
    {
        self::assertCount(
            1,
            $this->subject->parse("version: 1\ndn: cn=foo,dc=x\ncn: foo\n"),
        );
    }

    public function test_it_rejects_an_unsupported_version(): void
    {
        $this->expectException(LdifParseException::class);

        $this->subject->parse("version: 2\ndn: cn=foo,dc=x\ncn: foo\n");
    }

    public function test_it_rejects_a_version_after_an_entry(): void
    {
        $this->expectException(LdifParseException::class);

        $this->subject->parse("dn: cn=foo,dc=x\ncn: foo\n\nversion: 1\n");
    }

    public function test_it_rejects_change_records(): void
    {
        $this->expectException(LdifParseException::class);
        $this->expectExceptionMessage('change records');

        $this->subject->parse("dn: cn=foo,dc=x\nchangetype: add\ncn: foo\n");
    }

    public function test_it_rejects_url_referenced_values(): void
    {
        $this->expectException(LdifParseException::class);
        $this->expectExceptionMessage('URL-referenced');

        $this->subject->parse("dn: cn=foo,dc=x\njpegPhoto:< file:///tmp/x.jpg\n");
    }

    public function test_it_reports_the_line_number_of_a_malformed_line(): void
    {
        try {
            $this->subject->parse("dn: cn=foo,dc=x\ncn: foo\nthis-has-no-colon\n");
            self::fail('Expected an LdifParseException.');
        } catch (LdifParseException $e) {
            self::assertSame(3, $e->getLineNumber());
            self::assertSame('this-has-no-colon', $e->getSourceLine());
        }
    }

    public function test_it_parses_an_empty_value(): void
    {
        $entry = $this->subject->parse("dn: cn=foo,dc=x\ndescription:\n")->toArray()[0];

        self::assertSame([''], $entry->get('description')?->getValues());
    }

    public function test_it_returns_no_entries_for_empty_input(): void
    {
        self::assertCount(0, $this->subject->parse(''));
    }
}
