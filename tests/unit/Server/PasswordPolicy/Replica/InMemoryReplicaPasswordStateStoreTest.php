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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy\Replica;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\InMemoryReplicaPasswordStateStore;
use PHPUnit\Framework\TestCase;

final class InMemoryReplicaPasswordStateStoreTest extends TestCase
{
    private const DN = 'cn=foo,dc=example,dc=com';

    private InMemoryReplicaPasswordStateStore $subject;

    protected function setUp(): void
    {
        $this->subject = new InMemoryReplicaPasswordStateStore();
    }

    public function test_load_is_empty_when_nothing_was_recorded(): void
    {
        self::assertTrue($this->subject->load(new Dn(self::DN))->isEmpty());
    }

    public function test_apply_persists_replace_changes(): void
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

    public function test_apply_reset_removes_a_previously_stored_attribute(): void
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

    public function test_state_is_keyed_by_the_canonical_dn(): void
    {
        $this->applyChanges(
            new Dn('CN=Foo,DC=Example,DC=Com'),
            OperationalChanges::of(Change::replace(
                PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
                '20260520120000Z',
            )),
        );

        self::assertFalse($this->subject->load(new Dn(self::DN))->isEmpty());
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
