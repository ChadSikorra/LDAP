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

namespace Tests\Performance\FreeDSx\Ldap\Asn1;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;

use function chr;
use function intdiv;
use function ord;
use function strlen;
use function substr;

/**
 * EXPLORATORY PROTOTYPE — not wired into the protocol path.
 *
 * A direct byte <-> domain codec for the single hottest LDAP PDU (SearchResultEntry),
 * used by the ASN.1 encode bench to measure the ceiling of skipping the generic
 * AbstractType "DOM" tree entirely.
 *
 * The current production path is two passes with full intermediate allocation:
 *
 *   encode:  Entry -> SearchResultEntry::toAsn1() (builds N*M+ AbstractType objects)
 *                  -> LdapEncoder::encode()       (recursively walks that tree)
 *   decode:  bytes -> LdapEncoder::decode()       (builds the same tree)
 *                  -> SearchResultEntry::fromAsn1() (walks it into Entry/Attribute)
 *
 * This codec collapses each direction into a single pass with zero AbstractType
 * allocation. Output is intended to be byte-identical to the production encoder for
 * this PDU (the bench asserts it), and decode produces an equal SearchResultEntry.
 *
 * It only handles the fixed SearchResultEntry shape (RFC 4511, 4.5.2):
 *
 *   SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
 *       objectName      LDAPDN,                       -- OCTET STRING
 *       attributes      PartialAttributeList }        -- SEQUENCE OF SEQUENCE {
 *           type        AttributeDescription,         --   OCTET STRING
 *           vals        SET OF AttributeValue } }     --   SET OF OCTET STRING
 *
 * Constant tag octets (UNIVERSAL unless noted), derived the same way BerEncoder does
 * (class | constructed-bit | tag-number):
 *   0x64  [APPLICATION 4] SEQUENCE  (0x40 | 0x20 | 4)
 *   0x30  SEQUENCE / SEQUENCE OF    (0x00 | 0x20 | 0x10)
 *   0x31  SET / SET OF              (0x00 | 0x20 | 0x11)
 *   0x04  OCTET STRING             (0x00 | 0x00 | 0x04)
 */
final class SearchResultEntryCodec
{
    private const TAG_APP_SEQUENCE = "\x64";

    private const TAG_SEQUENCE = "\x30";

    private const TAG_SET = "\x31";

    private const TAG_OCTET_STRING = "\x04";

    /**
     * Direct Entry -> SearchResultEntry BER bytes, single pass, no AbstractType tree.
     *
     * Children are emitted to strings bottom-up so each definite length is just the
     * strlen() of the content already built — the same lengths the production encoder
     * computes after recursing.
     */
    public static function encode(Entry $entry): string
    {
        $attributes = '';
        foreach ($entry->getAttributes() as $attribute) {
            $values = '';
            foreach ($attribute->getValues() as $value) {
                $values .= self::TAG_OCTET_STRING . self::length(strlen($value)) . $value;
            }
            $name = $attribute->getDescription();
            $partial = self::TAG_OCTET_STRING . self::length(strlen($name)) . $name
                . self::TAG_SET . self::length(strlen($values)) . $values;
            $attributes .= self::TAG_SEQUENCE . self::length(strlen($partial)) . $partial;
        }

        $dn = $entry->getDn()->toString();
        $content = self::TAG_OCTET_STRING . self::length(strlen($dn)) . $dn
            . self::TAG_SEQUENCE . self::length(strlen($attributes)) . $attributes;

        return self::TAG_APP_SEQUENCE . self::length(strlen($content)) . $content;
    }

    /**
     * Direct BER bytes -> SearchResultEntry, single pass cursor reader (a pull parser
     * over the byte string), producing Entry/Attribute objects identical to the
     * production fromAsn1() path. Tags are asserted to fail loudly on a malformed PDU.
     *
     * @throws EncoderException
     */
    public static function decode(string $bytes): SearchResultEntry
    {
        $pos = 0;
        $max = strlen($bytes);

        self::expect($bytes, $pos, "\x64", 'SearchResultEntry envelope');
        self::readLength($bytes, $pos, $max);

        self::expect($bytes, $pos, "\x04", 'objectName');
        $dnLen = self::readLength($bytes, $pos, $max);
        $dn = substr($bytes, $pos, $dnLen);
        $pos += $dnLen;

        self::expect($bytes, $pos, "\x30", 'PartialAttributeList');
        $attrsLen = self::readLength($bytes, $pos, $max);
        $attrsEnd = $pos + $attrsLen;

        $attributes = [];
        while ($pos < $attrsEnd) {
            self::expect($bytes, $pos, "\x30", 'PartialAttribute');
            self::readLength($bytes, $pos, $max);

            self::expect($bytes, $pos, "\x04", 'attribute type');
            $nameLen = self::readLength($bytes, $pos, $max);
            $name = substr($bytes, $pos, $nameLen);
            $pos += $nameLen;

            self::expect($bytes, $pos, "\x31", 'attribute vals');
            $setLen = self::readLength($bytes, $pos, $max);
            $setEnd = $pos + $setLen;

            $values = [];
            while ($pos < $setEnd) {
                self::expect($bytes, $pos, "\x04", 'attribute value');
                $valLen = self::readLength($bytes, $pos, $max);
                $values[] = substr($bytes, $pos, $valLen);
                $pos += $valLen;
            }

            $attributes[] = Attribute::fromArray($name, $values);
        }

        return new SearchResultEntry(Entry::raw(
            new Dn($dn),
            $attributes,
        ));
    }

    /**
     * Definite-form length octets, matching BerEncoder::encodeLongDefiniteLength().
     */
    private static function length(int $num): string
    {
        if ($num < 128) {
            return chr($num);
        }

        $bytes = '';
        while ($num) {
            $bytes = chr($num % 256) . $bytes;
            $num = intdiv($num, 256);
        }

        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    /**
     * Read a definite-form length, mirroring BerEncoder's decode rules (short form,
     * long form base-256; indefinite form is rejected).
     *
     * @throws EncoderException
     */
    private static function readLength(string $bytes, int &$pos, int $max): int
    {
        if ($pos >= $max) {
            throw new EncoderException('Unexpected end of data while reading a length.');
        }
        $first = ord($bytes[$pos++]);
        if ($first < 128) {
            return $first;
        }
        if ($first === 128) {
            throw new EncoderException('Indefinite length encoding is not supported.');
        }

        $lengthOfLength = $first & 0x7f;
        $length = 0;
        for ($i = 0; $i < $lengthOfLength; $i++) {
            if ($pos >= $max) {
                throw new EncoderException('Unexpected end of data while reading a long length.');
            }
            $length = $length * 256 + ord($bytes[$pos++]);
        }

        return $length;
    }

    /**
     * @throws EncoderException
     */
    private static function expect(string $bytes, int &$pos, string $tag, string $what): void
    {
        if (!isset($bytes[$pos]) || $bytes[$pos] !== $tag) {
            throw new EncoderException("Malformed SearchResultEntry: expected $what.");
        }
        $pos++;
    }
}
