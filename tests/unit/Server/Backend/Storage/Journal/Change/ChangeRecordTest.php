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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Journal\Change;

use DateTimeImmutable;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use PHPUnit\Framework\TestCase;

final class ChangeRecordTest extends TestCase
{
    public function test_to_array_is_the_full_canonical_shape(): void
    {
        $record = new ChangeRecord(
            seq: 3,
            origin: new ReplicaId('node-a'),
            createdAt: new DateTimeImmutable('2025-05-15T12:00:00+00:00'),
            change: new PendingChange(
                changeType: ChangeType::ModRdn,
                dn: new Dn('cn=b,dc=example,dc=com'),
                entryUuid: '11111111-1111-4111-8111-111111111111',
                authzId: AuthzId::fromDn(new Dn('cn=admin,dc=example,dc=com')),
                previousDn: new Dn('cn=a,dc=example,dc=com'),
                preImage: new Entry(
                    new Dn('cn=b,dc=example,dc=com'),
                    new Attribute('cn', 'b'),
                    new Attribute('userPassword', 'secret'),
                ),
            ),
        );

        self::assertSame(
            [
                'seq' => 3,
                'origin' => 'node-a',
                'created_at' => '2025-05-15T12:00:00+00:00',
                'change_type' => 'modrdn',
                'dn' => 'cn=b,dc=example,dc=com',
                'entry_uuid' => '11111111-1111-4111-8111-111111111111',
                'authz_id' => 'dn:cn=admin,dc=example,dc=com',
                'previous_dn' => 'cn=a,dc=example,dc=com',
                'pre_image' => [
                    'cn' => ['b'],
                    'userPassword' => ['secret'],
                ],
            ],
            $record->toArray(),
        );
    }
}
