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

namespace Tests\Integration\FreeDSx\Ldap\Security;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * End-to-end tests for RuleBasedAccessControl.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class AclIntegrationTest extends ServerTestCase
{
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-acl',
            'tcp',
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-acl');
        parent::setUp();
    }

    public function testAnonymousSearchIsDenied(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
    }

    public function testAuthenticatedUserCanSearch(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useBaseScope(),
        );

        self::assertCount(1, $entries);
    }

    public function testAuthenticatedUserCanCompare(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $result = $this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'sn',
            'Smith',
        );

        self::assertTrue($result);
    }

    public function testAuthenticatedUserAddIsDenied(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=denied-add,dc=foo,dc=bar',
            ['cn' => 'denied-add', 'sn' => 'Denied', 'objectClass' => 'inetOrgPerson'],
        ));
    }

    public function testAuthenticatedUserDeleteIsDenied(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->delete('cn=alice,ou=people,dc=foo,dc=bar');
    }

    public function testAuthenticatedUserModifyDnIsDenied(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->rename(
            'cn=user,dc=foo,dc=bar',
            'cn=user-renamed',
            true,
        );
    }

    public function testUserCanModifyOwnEntry(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $entry = Entry::fromArray('cn=user,dc=foo,dc=bar');
        $entry->set('sn', 'UpdatedUser');
        $this->ldapClient()->update($entry);

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('sn', 'UpdatedUser'))
                ->base('cn=user,dc=foo,dc=bar')
                ->useBaseScope(),
        );

        self::assertCount(1, $results);
    }

    public function testUserCannotModifyOtherEntry(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $entry = Entry::fromArray('cn=alice,ou=people,dc=foo,dc=bar');
        $entry->set('sn', 'ShouldNotWork');
        $this->ldapClient()->update($entry);
    }

    public function testGroupMemberCanAddEntry(): void
    {
        $this->ldapClient()->bind('cn=admin,dc=foo,dc=bar', 'adminpass');

        $this->ldapClient()->create(Entry::fromArray(
            'cn=acl-temp-add,dc=foo,dc=bar',
            ['cn' => 'acl-temp-add', 'sn' => 'Temp', 'objectClass' => 'inetOrgPerson'],
        ));

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'acl-temp-add'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $results);

        $this->ldapClient()->delete('cn=acl-temp-add,dc=foo,dc=bar');
    }

    public function testGroupMemberCanDeleteEntry(): void
    {
        $this->ldapClient()->bind('cn=admin,dc=foo,dc=bar', 'adminpass');

        $this->ldapClient()->create(Entry::fromArray(
            'cn=acl-temp-delete,dc=foo,dc=bar',
            ['cn' => 'acl-temp-delete', 'sn' => 'Temp', 'objectClass' => 'inetOrgPerson'],
        ));

        $this->ldapClient()->delete('cn=acl-temp-delete,dc=foo,dc=bar');

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'acl-temp-delete'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(0, $results);
    }

    public function testGroupMemberCanModifyAnyEntry(): void
    {
        $this->ldapClient()->bind('cn=admin,dc=foo,dc=bar', 'adminpass');

        $entry = Entry::fromArray('cn=alice,ou=people,dc=foo,dc=bar');
        $entry->set('sn', 'AdminModified');
        $this->ldapClient()->update($entry);

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('sn', 'AdminModified'))
                ->base('ou=people,dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $results);

        $revert = Entry::fromArray('cn=alice,ou=people,dc=foo,dc=bar');
        $revert->set('sn', 'Smith');
        $this->ldapClient()->update($revert);
    }

    public function testUserCanRenameWithinAllowedSubtree(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->ldapClient()->rename(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'cn=alice-renamed',
            true,
        );

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice-renamed'))
                ->base('ou=people,dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $results);

        $this->ldapClient()->rename(
            'cn=alice-renamed,ou=people,dc=foo,dc=bar',
            'cn=alice',
            true,
        );
    }

    public function testUserCannotMoveEntryToRestrictedParent(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->move(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'dc=foo,dc=bar',
        );
    }

    public function testUserPasswordHiddenFromOtherUsers(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->setAttributes('cn', 'sn', 'userPassword'),
        );

        $alice = $results->first();
        self::assertNotNull($alice);
        self::assertNull($alice->get('userPassword'));
    }

    public function testUserPasswordVisibleToSelf(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'user'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->setAttributes('cn', 'userPassword'),
        );

        $user = $results->first();
        self::assertNotNull($user);
        self::assertNotNull($user->get('userPassword'));
    }

    public function testUserPasswordVisibleToGroupMember(): void
    {
        $this->ldapClient()->bind('cn=admin,dc=foo,dc=bar', 'adminpass');

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->setAttributes('cn', 'userPassword'),
        );

        $alice = $results->first();
        self::assertNotNull($alice);
        self::assertNotNull($alice->get('userPassword'));
    }
}
