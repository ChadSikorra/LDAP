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

namespace Tests\Unit\FreeDSx\Ldap\Server\Storage\Adapter;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\Storage\Adapter\InMemoryStorageAdapter;
use PHPUnit\Framework\TestCase;

final class InMemoryStorageAdapterTest extends TestCase
{
    private InMemoryStorageAdapter $subject;

    private Entry $alice;

    private Entry $bob;

    private Entry $base;

    protected function setUp(): void
    {
        $this->base = new Entry(
            new Dn('dc=example,dc=com'),
            new Attribute('dc', 'example'),
            new Attribute('objectClass', 'dcObject'),
        );
        $this->alice = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
            new Attribute('userPassword', 'secret'),
        );
        $this->bob = new Entry(
            new Dn('cn=Bob,ou=People,dc=example,dc=com'),
            new Attribute('cn', 'Bob'),
        );

        $this->subject = new InMemoryStorageAdapter($this->base, $this->alice, $this->bob);
    }

    // -------------------------------------------------------------------------
    // get
    // -------------------------------------------------------------------------

    public function test_get_returns_entry_by_dn(): void
    {
        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));
        self::assertNotNull($entry);
        self::assertSame('cn=Alice,dc=example,dc=com', $entry->getDn()->toString());
    }

    public function test_get_is_case_insensitive(): void
    {
        $entry = $this->subject->get(new Dn('CN=ALICE,DC=EXAMPLE,DC=COM'));
        self::assertNotNull($entry);
    }

    public function test_get_returns_null_for_missing_dn(): void
    {
        self::assertNull($this->subject->get(new Dn('cn=Charlie,dc=example,dc=com')));
    }

    // -------------------------------------------------------------------------
    // list / scope
    // -------------------------------------------------------------------------

    public function test_list_base_scope_returns_only_base(): void
    {
        $entries = $this->subject->list(new Dn('dc=example,dc=com'), SearchRequest::SCOPE_BASE_OBJECT);
        self::assertCount(1, $entries);
        self::assertSame('dc=example,dc=com', $entries->first()?->getDn()->toString());
    }

    public function test_list_single_level_returns_direct_children(): void
    {
        $entries = $this->subject->list(new Dn('dc=example,dc=com'), SearchRequest::SCOPE_SINGLE_LEVEL);
        // Only alice is a direct child of dc=example,dc=com; bob is under ou=People
        self::assertCount(1, $entries);
        self::assertSame('cn=Alice,dc=example,dc=com', $entries->first()?->getDn()->toString());
    }

    public function test_list_subtree_returns_base_and_all_descendants(): void
    {
        $entries = $this->subject->list(new Dn('dc=example,dc=com'), SearchRequest::SCOPE_WHOLE_SUBTREE);
        self::assertCount(3, $entries);
    }

    // -------------------------------------------------------------------------
    // verifyPassword
    // -------------------------------------------------------------------------

    public function test_verify_password_returns_true_for_correct_plain_password(): void
    {
        self::assertTrue(
            $this->subject->verifyPassword(new Dn('cn=Alice,dc=example,dc=com'), 'secret')
        );
    }

    public function test_verify_password_returns_false_for_wrong_password(): void
    {
        self::assertFalse(
            $this->subject->verifyPassword(new Dn('cn=Alice,dc=example,dc=com'), 'wrong')
        );
    }

    public function test_verify_password_returns_false_for_missing_entry(): void
    {
        self::assertFalse(
            $this->subject->verifyPassword(new Dn('cn=Unknown,dc=example,dc=com'), 'secret')
        );
    }

    public function test_verify_password_supports_sha_hash(): void
    {
        $hashed = '{SHA}' . base64_encode(sha1('mypassword', true));
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );
        $adapter = new InMemoryStorageAdapter($entry);

        self::assertTrue($adapter->verifyPassword(new Dn('cn=Test,dc=example,dc=com'), 'mypassword'));
        self::assertFalse($adapter->verifyPassword(new Dn('cn=Test,dc=example,dc=com'), 'wrong'));
    }

    // -------------------------------------------------------------------------
    // add
    // -------------------------------------------------------------------------

    public function test_add_stores_entry(): void
    {
        $adapter = new InMemoryStorageAdapter();
        $entry = new Entry(new Dn('cn=New,dc=example,dc=com'), new Attribute('cn', 'New'));
        $adapter->add($entry);

        self::assertNotNull($adapter->get(new Dn('cn=New,dc=example,dc=com')));
    }

    // -------------------------------------------------------------------------
    // delete
    // -------------------------------------------------------------------------

    public function test_delete_removes_entry(): void
    {
        $this->subject->delete(new Dn('cn=Alice,dc=example,dc=com'));
        self::assertNull($this->subject->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    // -------------------------------------------------------------------------
    // update
    // -------------------------------------------------------------------------

    public function test_update_add_attribute_value(): void
    {
        $this->subject->update(
            new Dn('cn=Alice,dc=example,dc=com'),
            [new Change(Change::TYPE_ADD, 'mail', 'alice@example.com')]
        );

        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));
        self::assertNotNull($entry);
        self::assertTrue($entry->get('mail')?->has('alice@example.com'));
    }

    public function test_update_replace_attribute_value(): void
    {
        $this->subject->update(
            new Dn('cn=Alice,dc=example,dc=com'),
            [new Change(Change::TYPE_REPLACE, 'cn', 'Alicia')]
        );

        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));
        self::assertSame(['Alicia'], $entry?->get('cn')?->getValues());
    }

    public function test_update_delete_attribute(): void
    {
        $this->subject->update(
            new Dn('cn=Alice,dc=example,dc=com'),
            [new Change(Change::TYPE_DELETE, 'userPassword')]
        );

        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));
        self::assertNull($entry?->get('userPassword'));
    }

    // -------------------------------------------------------------------------
    // move
    // -------------------------------------------------------------------------

    public function test_move_renames_entry(): void
    {
        $this->subject->move(
            new Dn('cn=Alice,dc=example,dc=com'),
            Rdn::create('cn=Alicia'),
            true,
            null,
        );

        self::assertNull($this->subject->get(new Dn('cn=Alice,dc=example,dc=com')));
        self::assertNotNull($this->subject->get(new Dn('cn=Alicia,dc=example,dc=com')));
    }

    public function test_move_to_new_parent(): void
    {
        $ou = new Entry(new Dn('ou=People,dc=example,dc=com'), new Attribute('ou', 'People'));
        $this->subject->add($ou);

        $this->subject->move(
            new Dn('cn=Alice,dc=example,dc=com'),
            Rdn::create('cn=Alice'),
            false,
            new Dn('ou=People,dc=example,dc=com'),
        );

        self::assertNull($this->subject->get(new Dn('cn=Alice,dc=example,dc=com')));
        self::assertNotNull($this->subject->get(new Dn('cn=Alice,ou=People,dc=example,dc=com')));
    }
}
