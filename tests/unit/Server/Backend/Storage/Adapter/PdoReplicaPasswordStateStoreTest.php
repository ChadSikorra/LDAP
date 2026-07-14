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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqliteFilterTranslator;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use PDO;
use PHPUnit\Framework\TestCase;

final class PdoReplicaPasswordStateStoreTest extends TestCase
{
    private const DN = 'cn=foo,dc=example,dc=com';

    private PDO $pdo;

    private PdoStorage $storage;

    private ReplicaPasswordStateStoreInterface $subject;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        PdoStorage::initialize(
            $this->pdo,
            new SqliteDialect(),
        );
        $this->storage = new PdoStorage(
            new SharedPdoConnectionProvider(
                $this->pdo,
                fn(): PDO => $this->pdo,
            ),
            new SqliteFilterTranslator(),
            new SqliteDialect(),
        );
        $this->subject = $this->storage->replicaPasswordStateStore();
    }

    public function test_load_is_empty_when_nothing_was_recorded(): void
    {
        self::assertTrue($this->subject->load(new Dn(self::DN))->isEmpty());
    }

    public function test_apply_persists_and_reloads_state(): void
    {
        $this->applyChanges(
            new Dn(self::DN),
            OperationalChanges::of(Change::replace(
                PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
                '20260520120000Z',
            )),
        );

        self::assertTrue(
            $this->subject
                ->load(new Dn(self::DN))
                ->toUserPasswordState(new Dn(self::DN))
                ->isLocked(),
        );
    }

    public function test_apply_reset_removes_the_row(): void
    {
        $dn = new Dn(self::DN);
        $this->applyChanges(
            $dn,
            OperationalChanges::of(Change::replace(
                PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
                '20260520120000Z',
            )),
        );

        $this->applyChanges(
            $dn,
            OperationalChanges::of(Change::reset(PasswordPolicyOid::NAME_PWD_FAILURE_TIME)),
        );

        self::assertTrue($this->subject->load($dn)->isEmpty());
    }

    public function test_local_state_survives_a_verbatim_entry_store(): void
    {
        $dn = new Dn(self::DN);
        $this->applyChanges(
            $dn,
            OperationalChanges::of(Change::replace(
                PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
                '20260520120000Z',
            )),
        );

        $this->storage->store(new Entry(
            $dn,
            new Attribute('cn', 'foo'),
        ));

        self::assertTrue(
            $this->subject
                ->load($dn)
                ->toUserPasswordState($dn)
                ->isLocked(),
        );
    }

    public function test_a_recorded_change_becomes_a_pending_forward(): void
    {
        $this->applyFailure('20260520120000Z');

        $pending = $this->subject->listUnforwarded();

        self::assertCount(
            1,
            $pending,
        );
        self::assertSame(
            self::DN,
            $pending[0]->dn->toString(),
        );
        self::assertSame(
            1,
            $pending[0]->sequence,
        );
    }

    public function test_marking_forwarded_clears_the_pending_entry(): void
    {
        $this->applyFailure('20260520120000Z');

        $this->subject->markForwarded(
            new Dn(self::DN),
            1,
        );

        self::assertSame(
            [],
            $this->subject->listUnforwarded(),
        );
    }

    public function test_marking_a_stale_sequence_leaves_a_newer_change_pending(): void
    {
        $this->applyFailure('20260520120000Z');
        $this->applyFailure('20260520120500Z');

        $this->subject->markForwarded(
            new Dn(self::DN),
            1,
        );

        $pending = $this->subject->listUnforwarded();

        self::assertCount(
            1,
            $pending,
        );
        self::assertSame(
            2,
            $pending[0]->sequence,
        );
    }

    private function applyFailure(string $time): void
    {
        $this->applyChanges(
            new Dn(self::DN),
            OperationalChanges::of(Change::replace(
                PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
                $time,
            )),
        );
    }

    private function applyChanges(
        Dn $dn,
        OperationalChanges $changes,
    ): void {
        $this->subject->atomicMutate(
            $dn,
            static fn(): OperationalChanges => $changes,
        );
    }
}
