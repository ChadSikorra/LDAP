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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Journal\Serializer;

use FreeDSx\Ldap\Server\Backend\Storage\Journal\Serializer\JsonlRowSerializer;
use PHPUnit\Framework\TestCase;

final class JsonlRowSerializerTest extends TestCase
{
    private JsonlRowSerializer $subject;

    protected function setUp(): void
    {
        $this->subject = new JsonlRowSerializer();
    }

    public function test_encode_produces_a_single_line_with_no_embedded_newline(): void
    {
        $line = $this->subject->encode([
            'seq' => 1,
            'dn' => "cn=a\nb,dc=example,dc=com",
            'pre_image' => null,
        ]);

        self::assertStringNotContainsString(
            "\n",
            $line,
        );
    }

    public function test_encode_then_decode_round_trips_a_row(): void
    {
        $row = [
            'seq' => 7,
            'origin' => 'node-a',
            'created_at' => 1_700_000_000_000_000,
            'dn' => 'cn=a,dc=example,dc=com',
            'previous_dn' => null,
            'pre_image' => 'AAECAw==',
        ];

        self::assertSame(
            $row,
            $this->subject->decode($this->subject->encode($row)),
        );
    }

    public function test_decode_returns_null_for_a_malformed_line(): void
    {
        self::assertNull($this->subject->decode('{not valid json'));
    }

    public function test_decode_returns_null_for_a_non_object_line(): void
    {
        self::assertNull($this->subject->decode('42'));
    }
}
