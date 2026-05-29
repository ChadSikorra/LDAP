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
use FreeDSx\Ldap\Ldif\LdifChanges;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use PHPUnit\Framework\TestCase;

final class LdifParserTest extends TestCase
{
    public function test_it_parses_a_single_content_record_with_multi_valued_attributes(): void
    {
        $result = LdifChanges::fromString(
            "dn: cn=foo,dc=example,dc=com\nobjectClass: top\nobjectClass: person\ncn: foo\nsn: Bar\n",
        );

        self::assertCount(1, $result);
        $entry = $result->entries()[0];
        self::assertSame(
            'cn=foo,dc=example,dc=com',
            $entry->getDn()->toString(),
        );
        self::assertSame(
            ['top', 'person'],
            $entry->get('objectClass')?->getValues(),
        );
        self::assertSame(
            ['Bar'],
            $entry->get('sn')?->getValues(),
        );
    }

    public function test_it_parses_multiple_records_separated_by_blank_lines(): void
    {
        $result = LdifChanges::fromString(
            "dn: cn=a,dc=x\ncn: a\n\ndn: cn=b,dc=x\ncn: b\n",
        );

        self::assertCount(
            2,
            $result,
        );
    }

    public function test_it_unfolds_continued_lines(): void
    {
        $entry = LdifChanges::fromString(
            "dn: cn=foo,dc=x\ndescription: this is a long\n  description value\n",
        )->entries()[0];

        self::assertSame(
            ['this is a long description value'],
            $entry->get('description')?->getValues(),
        );
    }

    public function test_it_decodes_a_base64_value(): void
    {
        $entry = LdifChanges::fromString(
            "dn: cn=foo,dc=x\ncn:: " . base64_encode('Bär') . "\n",
        )->entries()[0];

        self::assertSame(
            ['Bär'],
            $entry->get('cn')?->getValues(),
        );
    }

    public function test_it_decodes_a_base64_dn(): void
    {
        $entry = LdifChanges::fromString(
            "dn:: " . base64_encode('cn=Bär,dc=x') . "\ncn: x\n",
        )->entries()[0];

        self::assertSame(
            'cn=Bär,dc=x',
            $entry->getDn()->toString(),
        );
    }

    public function test_it_skips_comments_including_folded_ones(): void
    {
        $result = LdifChanges::fromString(
            "# a top comment\ndn: cn=foo,dc=x\n# inline comment\n# folded\n more comment\ncn: foo\n",
        );

        self::assertCount(1, $result);
        self::assertSame(
            ['foo'],
            $result->entries()[0]->get('cn')?->getValues(),
        );
    }

    public function test_it_accepts_a_version_one_header(): void
    {
        self::assertCount(
            1,
            LdifChanges::fromString("version: 1\ndn: cn=foo,dc=x\ncn: foo\n"),
        );
    }

    public function test_it_rejects_an_unsupported_version(): void
    {
        $this->expectException(LdifParseException::class);

        LdifChanges::fromString("version: 2\ndn: cn=foo,dc=x\ncn: foo\n");
    }

    public function test_it_rejects_a_version_after_a_record(): void
    {
        $this->expectException(LdifParseException::class);

        LdifChanges::fromString("dn: cn=foo,dc=x\ncn: foo\n\nversion: 1\n");
    }

    public function test_it_parses_a_mixed_file_with_content_and_change_records(): void
    {
        $result = LdifChanges::fromString(
            "dn: cn=foo,dc=x\ncn: foo\nsn: Bar\n"
            . "\n"
            . "dn: cn=baz,dc=x\nchangetype: modify\nreplace: sn\nsn: Quux\n-\n",
        );

        self::assertCount(2, $result);
        self::assertInstanceOf(
            AddRequest::class,
            $result->toArray()[0],
        );
        self::assertInstanceOf(
            ModifyRequest::class,
            $result->toArray()[1],
        );
    }

    public function test_it_rejects_url_referenced_values(): void
    {
        $this->expectException(LdifParseException::class);
        $this->expectExceptionMessage('URL-referenced');

        LdifChanges::fromString("dn: cn=foo,dc=x\njpegPhoto:< file:///tmp/x.jpg\n");
    }

    public function test_it_reports_the_line_number_of_a_malformed_line(): void
    {
        try {
            LdifChanges::fromString("dn: cn=foo,dc=x\ncn: foo\nthis-has-no-colon\n");
            self::fail('Expected an LdifParseException.');
        } catch (LdifParseException $e) {
            self::assertSame(3, $e->getLineNumber());
            self::assertSame(
                'this-has-no-colon',
                $e->getSourceLine(),
            );
        }
    }

    public function test_it_parses_an_empty_value(): void
    {
        $entry = LdifChanges::fromString("dn: cn=foo,dc=x\ndescription:\n")->entries()[0];

        self::assertSame(
            [''],
            $entry->get('description')?->getValues(),
        );
    }

    public function test_it_returns_no_records_for_empty_input(): void
    {
        self::assertCount(0, LdifChanges::fromString(''));
    }
}
