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

namespace Tests\Unit\FreeDSx\Ldap\Sync\Consumer;

use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Result\EntryResult;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Sync\Consumer\ChangeApplierInterface;
use FreeDSx\Ldap\Sync\Consumer\VerbatimStorageApplier;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Session;
use PHPUnit\Framework\TestCase;

final class VerbatimStorageApplierTest extends TestCase
{
    private InMemoryStorage $storage;

    private ChangeApplierInterface $subject;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
        $this->subject = new VerbatimStorageApplier($this->storage);
    }

    public function test_an_add_stores_the_entry(): void
    {
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                $this->entry('cn=alice,dc=example,dc=com'),
            ),
            $this->refreshSession(),
        );

        self::assertTrue($this->exists('cn=alice,dc=example,dc=com'));
    }

    public function test_a_modify_replaces_the_stored_entry(): void
    {
        $session = $this->refreshSession();

        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                new Entry(
                    'cn=bob,dc=example,dc=com',
                    new Attribute('cn', 'bob'),
                    new Attribute('sn', 'Old'),
                ),
            ),
            $session,
        );
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_MODIFY,
                new Entry(
                    'cn=bob,dc=example,dc=com',
                    new Attribute('cn', 'bob'),
                    new Attribute('sn', 'New'),
                ),
            ),
            $session,
        );

        self::assertSame(
            'New',
            $this->value('cn=bob,dc=example,dc=com', 'sn'),
        );
    }

    public function test_a_delete_removes_the_entry(): void
    {
        $this->storage->store($this->entry('cn=carol,dc=example,dc=com'));

        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_DELETE,
                $this->entry('cn=carol,dc=example,dc=com'),
            ),
            $this->refreshSession(),
        );

        self::assertFalse($this->exists('cn=carol,dc=example,dc=com'));
    }

    public function test_reconcile_removes_locals_absent_from_the_present_phase(): void
    {
        foreach (['a', 'b', 'c'] as $cn) {
            $this->storage->store($this->entry("cn=$cn,dc=example,dc=com"));
        }

        $session = $this->refreshSession();
        $this->subject->beginRefresh();
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                $this->entry('cn=a,dc=example,dc=com'),
            ),
            $session,
        );
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                $this->entry('cn=b,dc=example,dc=com'),
            ),
            $session,
        );
        $this->subject->reconcile();

        self::assertTrue($this->exists('cn=a,dc=example,dc=com'));
        self::assertTrue($this->exists('cn=b,dc=example,dc=com'));
        self::assertFalse($this->exists('cn=c,dc=example,dc=com'));
    }

    public function test_a_rename_deletes_the_old_dn_and_keeps_the_new(): void
    {
        // The replica holds the entry at its old DN; the refresh presents it only at the new DN.
        $this->storage->store($this->entry('cn=old,dc=example,dc=com'));

        $session = $this->refreshSession();
        $this->subject->beginRefresh();
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                $this->entry('cn=new,dc=example,dc=com'),
            ),
            $session,
        );
        $this->subject->reconcile();

        self::assertFalse($this->exists('cn=old,dc=example,dc=com'));
        self::assertTrue($this->exists('cn=new,dc=example,dc=com'));
    }

    public function test_begin_refresh_clears_the_previous_present_set(): void
    {
        $session = $this->refreshSession();

        $this->subject->beginRefresh();
        $this->subject->apply(
            $this->syncResult(
                SyncStateControl::STATE_ADD,
                $this->entry('cn=a,dc=example,dc=com'),
            ),
            $session,
        );

        // A second refresh presents nothing; the first refresh's present-set must not protect the entry.
        $this->subject->beginRefresh();
        $this->subject->reconcile();

        self::assertFalse($this->exists('cn=a,dc=example,dc=com'));
    }

    private function entry(string $dn): Entry
    {
        return new Entry(
            $dn,
            new Attribute('cn', 'x'),
        );
    }

    private function syncResult(
        int $state,
        Entry $entry,
    ): SyncEntryResult {
        $message = new LdapMessageResponse(
            1,
            new SearchResultEntry($entry),
            new SyncStateControl($state, 'uuid-' . $entry->getDn()->toString()),
        );

        return new SyncEntryResult(new EntryResult($message));
    }

    private function refreshSession(): Session
    {
        return new Session(
            Session::MODE_LISTEN,
            null,
        );
    }

    private function exists(string $dn): bool
    {
        return $this->storage->find((new Dn($dn))->normalize()) !== null;
    }

    private function value(
        string $dn,
        string $attribute,
    ): ?string {
        $entry = $this->storage->find((new Dn($dn))->normalize());

        if ($entry === null) {
            return null;
        }

        $values = $entry->get($attribute)?->getValues() ?? [];

        return $values[0] ?? null;
    }
}
