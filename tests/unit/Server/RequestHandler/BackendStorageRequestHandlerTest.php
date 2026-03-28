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

namespace Tests\Unit\FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\BackendStorageRequestHandler;
use FreeDSx\Ldap\Server\Storage\Adapter\InMemoryStorageAdapter;
use FreeDSx\Ldap\Server\Storage\ReadableStorageAdapterInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class BackendStorageRequestHandlerTest extends TestCase
{
    private BackendStorageRequestHandler $subject;

    private InMemoryStorageAdapter $adapter;

    private RequestContext&MockObject $mockContext;

    private Entry $alice;

    protected function setUp(): void
    {
        $this->alice = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('objectClass', 'inetOrgPerson'),
            new Attribute('userPassword', 'secret'),
        );

        $this->adapter = new InMemoryStorageAdapter(
            new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
            $this->alice,
        );

        $this->subject = new BackendStorageRequestHandler($this->adapter);
        $this->mockContext = $this->createMock(RequestContext::class);
    }

    // -------------------------------------------------------------------------
    // search
    // -------------------------------------------------------------------------

    public function test_search_returns_matching_entries(): void
    {
        $request = Operations::search(Filters::equal('cn', 'Alice'));
        $request->setBaseDn('dc=example,dc=com');
        $request->useSubtreeScope();

        $entries = $this->subject->search($this->mockContext, $request);

        self::assertCount(1, $entries);
        self::assertSame('cn=Alice,dc=example,dc=com', $entries->first()?->getDn()->toString());
    }

    public function test_search_returns_empty_when_no_match(): void
    {
        $request = Operations::search(Filters::equal('cn', 'Bob'));
        $request->setBaseDn('dc=example,dc=com');
        $request->useSubtreeScope();

        $entries = $this->subject->search($this->mockContext, $request);

        self::assertCount(0, $entries);
    }

    public function test_search_throws_when_no_base_dn(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        $request = Operations::search(Filters::present('cn'));
        $this->subject->search($this->mockContext, $request);
    }

    public function test_search_filters_requested_attributes(): void
    {
        $request = Operations::search(Filters::equal('cn', 'Alice'), 'cn');
        $request->setBaseDn('dc=example,dc=com');
        $request->useSubtreeScope();

        $entries = $this->subject->search($this->mockContext, $request);
        $entry = $entries->first();

        self::assertNotNull($entry);
        self::assertNotNull($entry->get('cn'));
        self::assertNull($entry->get('sn'));
    }

    public function test_search_returns_no_attributes_for_1_1(): void
    {
        $request = Operations::search(Filters::equal('cn', 'Alice'), '1.1');
        $request->setBaseDn('dc=example,dc=com');
        $request->useSubtreeScope();

        $entries = $this->subject->search($this->mockContext, $request);
        $entry = $entries->first();

        self::assertNotNull($entry);
        self::assertCount(0, $entry->getAttributes());
    }

    // -------------------------------------------------------------------------
    // bind
    // -------------------------------------------------------------------------

    public function test_bind_returns_true_for_valid_credentials(): void
    {
        self::assertTrue(
            $this->subject->bind('cn=Alice,dc=example,dc=com', 'secret')
        );
    }

    public function test_bind_returns_false_for_wrong_password(): void
    {
        self::assertFalse(
            $this->subject->bind('cn=Alice,dc=example,dc=com', 'wrong')
        );
    }

    // -------------------------------------------------------------------------
    // add
    // -------------------------------------------------------------------------

    public function test_add_stores_new_entry(): void
    {
        $entry = new Entry(new Dn('cn=Bob,dc=example,dc=com'), new Attribute('cn', 'Bob'));
        $this->subject->add($this->mockContext, new AddRequest($entry));

        self::assertNotNull($this->adapter->get(new Dn('cn=Bob,dc=example,dc=com')));
    }

    public function test_add_throws_when_entry_already_exists(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        $this->subject->add($this->mockContext, new AddRequest($this->alice));
    }

    // -------------------------------------------------------------------------
    // delete
    // -------------------------------------------------------------------------

    public function test_delete_removes_entry(): void
    {
        $this->subject->delete($this->mockContext, new DeleteRequest('cn=Alice,dc=example,dc=com'));

        self::assertNull($this->adapter->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_delete_throws_when_entry_missing(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->subject->delete($this->mockContext, new DeleteRequest('cn=Unknown,dc=example,dc=com'));
    }

    public function test_delete_throws_when_entry_has_children(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NOT_ALLOWED_ON_NON_LEAF);

        // dc=example,dc=com has alice as a child
        $this->subject->delete($this->mockContext, new DeleteRequest('dc=example,dc=com'));
    }

    // -------------------------------------------------------------------------
    // modify
    // -------------------------------------------------------------------------

    public function test_modify_updates_entry(): void
    {
        $this->subject->modify(
            $this->mockContext,
            new ModifyRequest('cn=Alice,dc=example,dc=com', new Change(Change::TYPE_REPLACE, 'sn', 'Jones'))
        );

        $entry = $this->adapter->get(new Dn('cn=Alice,dc=example,dc=com'));
        self::assertSame(['Jones'], $entry?->get('sn')?->getValues());
    }

    public function test_modify_throws_when_entry_missing(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->subject->modify(
            $this->mockContext,
            new ModifyRequest('cn=Unknown,dc=example,dc=com', new Change(Change::TYPE_REPLACE, 'sn', 'Jones'))
        );
    }

    // -------------------------------------------------------------------------
    // modifyDn
    // -------------------------------------------------------------------------

    public function test_modify_dn_renames_entry(): void
    {
        $this->subject->modifyDn(
            $this->mockContext,
            new ModifyDnRequest('cn=Alice,dc=example,dc=com', 'cn=Alicia', true)
        );

        self::assertNull($this->adapter->get(new Dn('cn=Alice,dc=example,dc=com')));
        self::assertNotNull($this->adapter->get(new Dn('cn=Alicia,dc=example,dc=com')));
    }

    public function test_modify_dn_throws_when_entry_missing(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->subject->modifyDn(
            $this->mockContext,
            new ModifyDnRequest('cn=Unknown,dc=example,dc=com', 'cn=New', true)
        );
    }

    // -------------------------------------------------------------------------
    // compare
    // -------------------------------------------------------------------------

    public function test_compare_returns_true_when_attribute_value_matches(): void
    {
        $request = new CompareRequest('cn=Alice,dc=example,dc=com', Filters::equal('cn', 'Alice'));
        self::assertTrue($this->subject->compare($this->mockContext, $request));
    }

    public function test_compare_returns_false_when_attribute_value_does_not_match(): void
    {
        $request = new CompareRequest('cn=Alice,dc=example,dc=com', Filters::equal('cn', 'Bob'));
        self::assertFalse($this->subject->compare($this->mockContext, $request));
    }

    public function test_compare_throws_when_entry_missing(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $request = new CompareRequest('cn=Unknown,dc=example,dc=com', Filters::equal('cn', 'Unknown'));
        $this->subject->compare($this->mockContext, $request);
    }

    // -------------------------------------------------------------------------
    // Write operations rejected for read-only adapter
    // -------------------------------------------------------------------------

    public function test_write_operations_rejected_for_read_only_adapter(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $readOnlyAdapter = $this->createMock(ReadableStorageAdapterInterface::class);
        $readOnlyAdapter->method('get')->willReturn(null);
        $handler = new BackendStorageRequestHandler($readOnlyAdapter);

        $handler->add(
            $this->mockContext,
            new AddRequest(new Entry(new Dn('cn=Test,dc=example,dc=com')))
        );
    }
}
