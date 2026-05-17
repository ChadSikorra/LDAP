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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy;

use DateTimeImmutable;
use DateTimeZone;
use FreeDSx\Ldap\Exception\PasswordPolicyException;
use FreeDSx\Ldap\Schema\Definition\SyntaxOid;
use FreeDSx\Ldap\Server\PasswordPolicy\HistoryEntry;
use PHPUnit\Framework\TestCase;

final class HistoryEntryTest extends TestCase
{
    public function test_encode_then_decode_round_trips(): void
    {
        $entry = new HistoryEntry(
            new DateTimeImmutable(
                '2025-04-15T10:30:00Z',
                new DateTimeZone('UTC'),
            ),
            SyntaxOid::OID_OCTET_STRING,
            '{SSHA}1234567890abcdef',
        );

        $decoded = HistoryEntry::decode($entry->encode());

        self::assertEquals(
            $entry->changedAt,
            $decoded->changedAt,
        );
        self::assertSame(
            $entry->syntaxOid,
            $decoded->syntaxOid,
        );
        self::assertSame(
            $entry->data,
            $decoded->data,
        );
    }

    public function test_decode_handles_data_containing_hash(): void
    {
        $data = '{SSHA}aaa#bbb#ccc';
        $wire = sprintf(
            '20250101000000Z#%s#%d#%s',
            SyntaxOid::OID_OCTET_STRING,
            strlen($data),
            $data,
        );

        $decoded = HistoryEntry::decode($wire);

        self::assertSame(
            $data,
            $decoded->data,
        );
    }

    public function test_encode_formats_time_as_generalized_time_utc(): void
    {
        $entry = new HistoryEntry(
            new DateTimeImmutable(
                '2025-04-15T10:30:00+05:00',
                new DateTimeZone('+05:00'),
            ),
            SyntaxOid::OID_OCTET_STRING,
            'x',
        );

        self::assertStringStartsWith(
            '20250415053000Z#',
            $entry->encode(),
        );
    }

    public function test_for_stored_password_defaults_to_octet_string(): void
    {
        $entry = HistoryEntry::forStoredPassword(
            new DateTimeImmutable(
                '2025-01-01T00:00:00Z',
                new DateTimeZone('UTC'),
            ),
            '{SSHA}abc',
        );

        self::assertSame(
            SyntaxOid::OID_OCTET_STRING,
            $entry->syntaxOid,
        );
    }

    public function test_decode_rejects_missing_time_delimiter(): void
    {
        $this->expectException(PasswordPolicyException::class);
        $this->expectExceptionMessage('missing time delimiter');

        HistoryEntry::decode('20250101000000Z');
    }

    public function test_decode_rejects_missing_syntax_delimiter(): void
    {
        $this->expectException(PasswordPolicyException::class);
        $this->expectExceptionMessage('missing syntax delimiter');

        HistoryEntry::decode('20250101000000Z#1.2.3.4');
    }

    public function test_decode_rejects_missing_length_delimiter(): void
    {
        $this->expectException(PasswordPolicyException::class);
        $this->expectExceptionMessage('missing length delimiter');

        HistoryEntry::decode('20250101000000Z#1.2.3.4#3');
    }

    public function test_decode_rejects_empty_syntax(): void
    {
        $this->expectException(PasswordPolicyException::class);
        $this->expectExceptionMessage('empty syntax OID');

        HistoryEntry::decode('20250101000000Z##3#abc');
    }

    public function test_decode_rejects_non_numeric_length(): void
    {
        $this->expectException(PasswordPolicyException::class);
        $this->expectExceptionMessage('length is not a non-negative integer');

        HistoryEntry::decode('20250101000000Z#1.2.3.4#abc#abc');
    }

    public function test_decode_rejects_length_mismatch(): void
    {
        $this->expectException(PasswordPolicyException::class);
        $this->expectExceptionMessage('declared length 10 does not match data length 3');

        HistoryEntry::decode('20250101000000Z#1.2.3.4#10#abc');
    }

    public function test_decode_rejects_invalid_time(): void
    {
        $this->expectException(PasswordPolicyException::class);
        $this->expectExceptionMessage('is not a valid GeneralizedTime');

        HistoryEntry::decode('not-a-time#1.2.3.4#3#abc');
    }

    public function test_decode_accepts_non_canonical_generalized_time_forms(): void
    {
        $decoded = HistoryEntry::decode('20250415080000-0500#1.3.6.1.4.1.1466.115.121.1.40#3#abc');

        self::assertSame(
            '2025-04-15T13:00:00+00:00',
            $decoded->changedAt->format('c'),
        );
    }
}
