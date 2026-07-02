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

namespace Tests\Support\FreeDSx\Ldap\Journal;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit\AuditSinkInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;

/**
 * Shared ChangeJournalingTrait contract tests.
 *
 * @mixin \PHPUnit\Framework\TestCase
 */
trait JournalingStorageContractTests
{
    public function test_append_change_records_to_the_configured_journal(): void
    {
        $storage = $this->makeJournalingStorage();
        $storage->configureJournal(new ChangeJournalConfig());
        $storage->appendChange($this->journalingChange());

        self::assertCount(
            1,
            iterator_to_array($storage->changeJournal()->read()),
        );
    }

    public function test_configure_journal_tees_appends_to_the_audit_sink(): void
    {
        $sink = $this->createMock(AuditSinkInterface::class);
        $sink->expects($this->once())
            ->method('write');
        $storage = $this->makeJournalingStorage();
        $storage->configureJournal(new ChangeJournalConfig(auditSink: $sink));

        $storage->appendChange($this->journalingChange());
    }

    public function test_the_journal_can_only_be_configured_once(): void
    {
        $storage = $this->makeJournalingStorage();
        $storage->configureJournal(new ChangeJournalConfig());

        $this->expectException(InvalidArgumentException::class);
        $storage->configureJournal(new ChangeJournalConfig());
    }

    public function test_reading_the_journal_before_it_is_configured_throws(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->makeJournalingStorage()->changeJournal();
    }

    abstract protected function makeJournalingStorage(): ChangeJournalingInterface;

    private function journalingChange(): PendingChange
    {
        return new PendingChange(
            changeType: ChangeType::Add,
            dn: new Dn('cn=a,dc=example,dc=com'),
            entryUuid: '11111111-1111-4111-8111-111111111111',
            authzId: AuthzId::anonymous(),
        );
    }
}
