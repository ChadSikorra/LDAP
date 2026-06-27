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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;

final class InMemoryChangeJournalTest extends TestCase
{
    private InMemoryChangeJournal $subject;

    private FrozenClock $clock;

    protected function setUp(): void
    {
        $this->clock = FrozenClock::fromString('2025-05-15T12:00:00');
        $this->subject = new InMemoryChangeJournal(
            new ReplicaId('node-a'),
            $this->clock,
        );
    }

    public function test_it_allocates_strictly_increasing_seq_numbers(): void
    {
        $first = $this->subject->append($this->change('cn=a,dc=example,dc=com'));
        $second = $this->subject->append($this->change('cn=b,dc=example,dc=com'));
        $third = $this->subject->append($this->change('cn=c,dc=example,dc=com'));

        self::assertSame(
            1,
            $first->seq,
        );
        self::assertSame(
            2,
            $second->seq,
        );
        self::assertSame(
            3,
            $third->seq,
        );
    }

    public function test_latest_seq_is_zero_until_anything_is_appended(): void
    {
        self::assertSame(
            0,
            $this->subject->latestSeq(),
        );

        $this->subject->append($this->change('cn=a,dc=example,dc=com'));

        self::assertSame(
            1,
            $this->subject->latestSeq(),
        );
    }

    public function test_it_stamps_the_record_with_origin_clock_and_change(): void
    {
        $change = $this->change('cn=a,dc=example,dc=com');

        $record = $this->subject->append($change);

        self::assertSame(
            $change,
            $record->change,
        );
        self::assertTrue($record->origin->equals(new ReplicaId('node-a')));
        self::assertEquals(
            $this->clock->now(),
            $record->createdAt,
        );
    }

    public function test_read_returns_only_records_after_the_given_seq(): void
    {
        $this->subject->append($this->change('cn=a,dc=example,dc=com'));
        $this->subject->append($this->change('cn=b,dc=example,dc=com'));
        $this->subject->append($this->change('cn=c,dc=example,dc=com'));

        $seqs = array_map(
            static fn(ChangeRecord $record): int => $record->seq,
            iterator_to_array($this->subject->read(1)),
        );

        self::assertSame(
            [2, 3],
            $seqs,
        );
    }

    public function test_read_without_an_argument_returns_everything(): void
    {
        $this->subject->append($this->change('cn=a,dc=example,dc=com'));
        $this->subject->append($this->change('cn=b,dc=example,dc=com'));

        self::assertCount(
            2,
            iterator_to_array($this->subject->read()),
        );
    }

    private function change(string $dn): PendingChange
    {
        return new PendingChange(
            changeType: ChangeType::Add,
            dn: new Dn($dn),
            entryUuid: '11111111-1111-4111-8111-111111111111',
            authzId: AuthzId::anonymous(),
        );
    }
}
