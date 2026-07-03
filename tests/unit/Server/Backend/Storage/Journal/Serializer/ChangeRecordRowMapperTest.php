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

use DateTimeImmutable;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Serializer\ChangeRecordRowMapper;
use PHPUnit\Framework\TestCase;

final class ChangeRecordRowMapperTest extends TestCase
{
    private const UUID = '11111111-1111-4111-8111-111111111111';

    private ChangeRecordRowMapper $subject;

    protected function setUp(): void
    {
        $this->subject = new ChangeRecordRowMapper();
    }

    public function test_to_row_derives_the_normalized_dn_fields(): void
    {
        $row = $this->subject->toRow($this->record(new PendingChange(
            changeType: ChangeType::Add,
            dn: new Dn('CN=Alice,DC=Example,DC=Com'),
            entryUuid: self::UUID,
            authzId: AuthzId::anonymous(),
        )));

        self::assertSame(
            'CN=Alice,DC=Example,DC=Com',
            $row['dn'],
        );
        self::assertSame(
            'cn=alice,dc=example,dc=com',
            $row['lc_dn'],
        );
        self::assertSame(
            'dc=example,dc=com',
            $row['lc_parent_dn'],
        );
    }

    public function test_to_row_and_from_row_round_trip_a_delete_with_a_pre_image(): void
    {
        $preImage = Entry::fromArray(
            'cn=a,dc=example,dc=com',
            ['cn' => ['a'], 'sn' => ['Doe']],
        );
        $record = $this->record(new PendingChange(
            changeType: ChangeType::Delete,
            dn: new Dn('cn=a,dc=example,dc=com'),
            entryUuid: self::UUID,
            authzId: AuthzId::fromDn(new Dn('cn=admin,dc=example,dc=com')),
            previousDn: new Dn('cn=old,dc=example,dc=com'),
            preImage: $preImage,
        ));

        $decoded = $this->subject->fromRow($this->subject->toRow($record));

        self::assertNotNull($decoded);
        self::assertSame(
            5,
            $decoded->seq,
        );
        self::assertTrue($decoded->origin->equals(new ReplicaId('node-a')));
        self::assertSame(
            ChangeType::Delete,
            $decoded->change->changeType,
        );
        self::assertSame(
            'cn=a,dc=example,dc=com',
            $decoded->change->dn->toString(),
        );
        self::assertSame(
            'cn=old,dc=example,dc=com',
            $decoded->change->previousDn?->toString(),
        );
        self::assertSame(
            'dn:cn=admin,dc=example,dc=com',
            $decoded->change->authzId->toString(),
        );
        self::assertNotNull($decoded->change->preImage);
        self::assertSame(
            ['cn' => ['a'], 'sn' => ['Doe']],
            $decoded->change->preImage->toArray(),
        );
    }

    public function test_from_row_returns_null_for_an_unknown_change_type(): void
    {
        $row = $this->subject->toRow($this->record(new PendingChange(
            changeType: ChangeType::Add,
            dn: new Dn('cn=a,dc=example,dc=com'),
            entryUuid: self::UUID,
            authzId: AuthzId::anonymous(),
        )));
        $row['change_type'] = 'not-a-real-type';

        self::assertNull($this->subject->fromRow($row));
    }

    public function test_from_row_ignores_a_corrupt_pre_image(): void
    {
        $row = $this->subject->toRow($this->record(new PendingChange(
            changeType: ChangeType::Delete,
            dn: new Dn('cn=a,dc=example,dc=com'),
            entryUuid: self::UUID,
            authzId: AuthzId::anonymous(),
            preImage: Entry::fromArray('cn=a,dc=example,dc=com', ['cn' => ['a']]),
        )));
        $row['pre_image'] = 'not-valid-base64-$$$';

        $decoded = $this->subject->fromRow($row);

        self::assertNotNull($decoded);
        self::assertNull($decoded->change->preImage);
    }

    private function record(PendingChange $change): ChangeRecord
    {
        return new ChangeRecord(
            seq: 5,
            origin: new ReplicaId('node-a'),
            createdAt: new DateTimeImmutable('2025-05-15T12:00:00+00:00'),
            change: $change,
        );
    }
}
