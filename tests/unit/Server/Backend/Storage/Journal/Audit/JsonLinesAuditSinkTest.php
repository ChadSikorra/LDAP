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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit;

use DateTimeImmutable;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit\JsonLinesAuditSink;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use PHPUnit\Framework\TestCase;

final class JsonLinesAuditSinkTest extends TestCase
{
    private string $path;

    private JsonLinesAuditSink $subject;

    protected function setUp(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'audit-test-');
        self::assertIsString($path);
        $this->path = $path;
        $this->subject = new JsonLinesAuditSink($this->path);
    }

    protected function tearDown(): void
    {
        @unlink($this->path);
    }

    public function test_it_writes_a_record_as_a_json_line_with_a_redacted_pre_image(): void
    {
        $this->subject->write($this->deleteRecord());

        self::assertSame(
            [
                'seq' => 7,
                'origin' => 'node-a',
                'created_at' => '2025-05-15T12:00:00+00:00',
                'change_type' => 'delete',
                'dn' => 'cn=a,dc=example,dc=com',
                'entry_uuid' => '11111111-1111-4111-8111-111111111111',
                'authz_id' => 'dn:cn=admin,dc=example,dc=com',
                'previous_dn' => null,
                'pre_image' => ['cn' => ['a']],
            ],
            $this->firstLine(),
        );
    }

    public function test_it_appends_one_line_per_record(): void
    {
        $this->subject->write($this->deleteRecord());
        $this->subject->write($this->deleteRecord());

        self::assertCount(
            2,
            file(
                $this->path,
                FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES,
            ) ?: [],
        );
    }

    /**
     * @return array<array-key, mixed>
     */
    private function firstLine(): array
    {
        $lines = file(
            $this->path,
            FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES,
        ) ?: [];

        if ($lines === []) {
            return [];
        }

        $decoded = json_decode(
            $lines[0],
            true,
            flags: JSON_THROW_ON_ERROR,
        );

        return is_array($decoded) ? $decoded : [];
    }

    private function deleteRecord(): ChangeRecord
    {
        return new ChangeRecord(
            seq: 7,
            origin: new ReplicaId('node-a'),
            createdAt: new DateTimeImmutable('2025-05-15T12:00:00+00:00'),
            change: new PendingChange(
                changeType: ChangeType::Delete,
                dn: new Dn('cn=a,dc=example,dc=com'),
                entryUuid: '11111111-1111-4111-8111-111111111111',
                authzId: AuthzId::fromDn(new Dn('cn=admin,dc=example,dc=com')),
                preImage: new Entry(
                    new Dn('cn=a,dc=example,dc=com'),
                    new Attribute('cn', 'a'),
                    new Attribute('userPassword', 'secret'),
                ),
            ),
        );
    }
}
