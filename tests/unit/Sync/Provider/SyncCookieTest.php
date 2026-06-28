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

namespace Tests\Unit\FreeDSx\Ldap\Sync\Provider;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Sync\Provider\Exception\MalformedSyncCookieException;
use FreeDSx\Ldap\Sync\Provider\SyncCookie;
use PHPUnit\Framework\TestCase;

final class SyncCookieTest extends TestCase
{
    public function test_encode_decode_preserves_the_origin_and_seq(): void
    {
        $decoded = SyncCookie::decode(
            (new SyncCookie(new ReplicaId('node-a'), 42))->encode(),
        );

        self::assertTrue($decoded->origin->equals(new ReplicaId('node-a')));
        self::assertSame(
            42,
            $decoded->seq,
        );
    }

    public function test_a_zero_seq_round_trips(): void
    {
        $decoded = SyncCookie::decode(
            (new SyncCookie(new ReplicaId('node-a'), 0))->encode(),
        );

        self::assertSame(
            0,
            $decoded->seq,
        );
    }

    public function test_it_rejects_a_negative_seq(): void
    {
        self::expectException(InvalidArgumentException::class);

        new SyncCookie(
            new ReplicaId('node-a'),
            -1,
        );
    }

    public function test_decode_rejects_invalid_base64(): void
    {
        self::expectException(MalformedSyncCookieException::class);

        SyncCookie::decode('@@not base64@@');
    }

    public function test_decode_rejects_an_unsupported_version(): void
    {
        $future = base64_encode((string) json_encode([
            'v' => 99,
            'origin' => 'node-a',
            'seq' => 1,
        ]));

        self::expectException(MalformedSyncCookieException::class);

        SyncCookie::decode($future);
    }
}
