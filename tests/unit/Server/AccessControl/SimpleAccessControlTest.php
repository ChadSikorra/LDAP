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

namespace Tests\Unit\FreeDSx\Ldap\Server\AccessControl;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\AccessControl\SimpleAccessControl;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;

final class SimpleAccessControlTest extends TestCase
{
    private SimpleAccessControl $subject;

    private Dn $dn;

    protected function setUp(): void
    {
        $this->subject = new SimpleAccessControl();
        $this->dn = new Dn('dc=foo,dc=bar');
    }

    public function test_it_should_deny_anonymous_search(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->subject->authorizeOperation(
            OperationType::Search,
            new AnonToken(),
            $this->dn,
        );
    }

    public function test_it_should_deny_anonymous_add(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->subject->authorizeOperation(
            OperationType::Add,
            new AnonToken(),
            $this->dn,
        );
    }

    public function test_it_should_deny_anonymous_modify(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->subject->authorizeOperation(
            OperationType::Modify,
            new AnonToken(),
            $this->dn,
        );
    }

    public function test_it_should_deny_anonymous_delete(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->subject->authorizeOperation(
            OperationType::Delete,
            new AnonToken(),
            $this->dn,
        );
    }

    public function test_it_should_deny_anonymous_modify_dn(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->subject->authorizeOperation(
            OperationType::ModifyDn,
            new AnonToken(),
            $this->dn,
        );
    }

    public function test_it_should_deny_anonymous_compare(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->subject->authorizeOperation(
            OperationType::Compare,
            new AnonToken(),
            $this->dn,
        );
    }

    public function test_it_should_allow_authenticated_search(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->authorizeOperation(
            OperationType::Search,
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            $this->dn,
        );
    }

    public function test_it_should_allow_authenticated_add(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->authorizeOperation(
            OperationType::Add,
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            $this->dn,
        );
    }

    public function test_it_should_return_entry_unchanged_from_filter_entry(): void
    {
        $entry = Entry::create('dc=foo,dc=bar', ['cn' => 'foo']);

        $result = $this->subject->filterEntry(
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            $entry,
        );

        self::assertSame(
            $entry,
            $result,
        );
    }

    public function test_filter_entry_returns_entry_unchanged_for_anonymous(): void
    {
        $entry = Entry::create('dc=foo,dc=bar', ['cn' => 'foo']);

        $result = $this->subject->filterEntry(
            new AnonToken(),
            $entry,
        );

        self::assertSame(
            $entry,
            $result,
        );
    }

    public function test_authorize_attribute_access_is_a_no_op(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->authorizeAttribute(
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            $this->dn,
            'userPassword',
        );
    }
}
