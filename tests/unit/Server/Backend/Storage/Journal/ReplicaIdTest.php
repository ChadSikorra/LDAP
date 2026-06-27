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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Journal;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use PHPUnit\Framework\TestCase;

final class ReplicaIdTest extends TestCase
{
    public function test_it_rejects_an_empty_value(): void
    {
        self::expectException(InvalidArgumentException::class);

        new ReplicaId('');
    }

    public function test_it_compares_by_value(): void
    {
        self::assertTrue((new ReplicaId('node-a'))->equals(new ReplicaId('node-a')));
        self::assertFalse((new ReplicaId('node-a'))->equals(new ReplicaId('node-b')));
    }

    public function test_it_stringifies_to_its_value(): void
    {
        self::assertSame(
            'node-a',
            (string) new ReplicaId('node-a'),
        );
    }

    public function test_local_is_the_default_single_master_identity(): void
    {
        self::assertSame(
            'local',
            (string) ReplicaId::local(),
        );
    }
}
