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

namespace Tests\Unit\FreeDSx\Ldap\Server\AccessControl\Subject;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\AccessControl\Subject\GroupSubjectMatcher;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class GroupSubjectMatcherTest extends TestCase
{
    private LdapBackendInterface&MockObject $mockBackend;

    private Dn $targetDn;

    protected function setUp(): void
    {
        $this->mockBackend = $this->createMock(LdapBackendInterface::class);
        $this->targetDn = new Dn('dc=foo,dc=bar');
    }

    public function test_it_should_match_when_bound_dn_is_a_group_member(): void
    {
        $groupEntry = Entry::create(
            'cn=admins,dc=foo,dc=bar',
            ['member' => ['cn=admin,dc=foo,dc=bar', 'cn=other,dc=foo,dc=bar']],
        );

        $this->mockBackend
            ->method('get')
            ->willReturn($groupEntry);

        $subject = new GroupSubjectMatcher('cn=admins,dc=foo,dc=bar');
        $subject->setBackend($this->mockBackend);

        self::assertTrue($subject->matches(
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            $this->targetDn,
        ));
    }

    public function test_it_should_match_case_insensitively(): void
    {
        $groupEntry = Entry::create(
            'cn=admins,dc=foo,dc=bar',
            ['member' => ['CN=Admin,DC=foo,DC=bar']],
        );

        $this->mockBackend
            ->method('get')
            ->willReturn($groupEntry);

        $subject = new GroupSubjectMatcher('cn=admins,dc=foo,dc=bar');
        $subject->setBackend($this->mockBackend);

        self::assertTrue($subject->matches(
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            $this->targetDn,
        ));
    }

    public function test_it_should_not_match_when_bound_dn_is_not_a_member(): void
    {
        $groupEntry = Entry::create(
            'cn=admins,dc=foo,dc=bar',
            ['member' => ['cn=other,dc=foo,dc=bar']],
        );

        $this->mockBackend
            ->method('get')
            ->willReturn($groupEntry);

        $subject = new GroupSubjectMatcher('cn=admins,dc=foo,dc=bar');
        $subject->setBackend($this->mockBackend);

        self::assertFalse($subject->matches(
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            $this->targetDn,
        ));
    }

    public function test_it_should_not_match_when_group_entry_is_not_found(): void
    {
        $this->mockBackend
            ->method('get')
            ->willReturn(null);

        $subject = new GroupSubjectMatcher('cn=admins,dc=foo,dc=bar');
        $subject->setBackend($this->mockBackend);

        self::assertFalse($subject->matches(
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            $this->targetDn,
        ));
    }

    public function test_it_should_not_match_when_backend_is_not_set(): void
    {
        $subject = new GroupSubjectMatcher('cn=admins,dc=foo,dc=bar');

        self::assertFalse($subject->matches(
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            $this->targetDn,
        ));
    }

    public function test_it_should_not_match_for_anonymous_token(): void
    {
        $this->mockBackend
            ->expects(self::never())
            ->method('get');

        $subject = new GroupSubjectMatcher('cn=admins,dc=foo,dc=bar');
        $subject->setBackend($this->mockBackend);

        self::assertFalse($subject->matches(
            new AnonToken(),
            $this->targetDn,
        ));
    }

    public function test_it_should_not_match_for_anonymous_token_even_with_matching_dn(): void
    {
        $this->mockBackend
            ->expects(self::never())
            ->method('get');

        $subject = new GroupSubjectMatcher('cn=admins,dc=foo,dc=bar');
        $subject->setBackend($this->mockBackend);

        self::assertFalse($subject->matches(
            new AnonToken('cn=admin,dc=foo,dc=bar'),
            $this->targetDn,
        ));
    }

    public function test_it_should_use_custom_member_attribute(): void
    {
        $groupEntry = Entry::create(
            'cn=admins,dc=foo,dc=bar',
            ['uniqueMember' => ['cn=admin,dc=foo,dc=bar']],
        );

        $this->mockBackend
            ->method('get')
            ->willReturn($groupEntry);

        $subject = new GroupSubjectMatcher(
            'cn=admins,dc=foo,dc=bar',
            'uniqueMember',
        );
        $subject->setBackend($this->mockBackend);

        self::assertTrue($subject->matches(
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            $this->targetDn,
        ));
    }

    public function test_it_should_fetch_group_entry_only_once_across_multiple_calls(): void
    {
        $groupEntry = Entry::create(
            'cn=admins,dc=foo,dc=bar',
            ['member' => ['cn=admin,dc=foo,dc=bar']],
        );

        $this->mockBackend
            ->expects(self::once())
            ->method('get')
            ->willReturn($groupEntry);

        $subject = new GroupSubjectMatcher('cn=admins,dc=foo,dc=bar');
        $subject->setBackend($this->mockBackend);

        $token = BindToken::fromDn(
            'cn=admin,dc=foo,dc=bar',
        );

        $subject->matches(
            $token,
            $this->targetDn,
        );
        $subject->matches(
            $token,
            $this->targetDn,
        );
        $subject->matches(
            $token,
            $this->targetDn,
        );
    }

    public function test_it_should_not_fetch_group_entry_for_anonymous_token(): void
    {
        $this->mockBackend
            ->expects(self::never())
            ->method('get');

        $subject = new GroupSubjectMatcher('cn=admins,dc=foo,dc=bar');
        $subject->setBackend($this->mockBackend);

        $subject->matches(
            new AnonToken(),
            $this->targetDn,
        );
    }

    public function test_it_should_fetch_group_entry_separately_per_token_id(): void
    {
        $groupEntry = Entry::create(
            'cn=admins,dc=foo,dc=bar',
            ['member' => ['cn=admin,dc=foo,dc=bar']],
        );

        $this->mockBackend
            ->expects(self::exactly(2))
            ->method('get')
            ->willReturn($groupEntry);

        $subject = new GroupSubjectMatcher('cn=admins,dc=foo,dc=bar');
        $subject->setBackend($this->mockBackend);

        $subject->matches(
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            $this->targetDn,
        );
        $subject->matches(
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            $this->targetDn,
        );
    }

    public function test_it_should_bypass_cache_when_max_cache_size_is_zero(): void
    {
        $groupEntry = Entry::create(
            'cn=admins,dc=foo,dc=bar',
            ['member' => ['cn=admin,dc=foo,dc=bar']],
        );

        $this->mockBackend
            ->expects(self::exactly(3))
            ->method('get')
            ->willReturn($groupEntry);

        $subject = new GroupSubjectMatcher(
            'cn=admins,dc=foo,dc=bar',
            'member',
            0,
        );
        $subject->setBackend($this->mockBackend);

        $token = BindToken::fromDn(
            'cn=admin,dc=foo,dc=bar',
        );

        $subject->matches($token, $this->targetDn);
        $subject->matches($token, $this->targetDn);
        $subject->matches($token, $this->targetDn);
    }

    public function test_it_should_match_when_member_dn_has_surrounding_whitespace(): void
    {
        $groupEntry = Entry::create(
            'cn=admins,dc=foo,dc=bar',
            ['member' => ['CN=Admin, DC=foo, DC=bar']],
        );

        $this->mockBackend
            ->method('get')
            ->willReturn($groupEntry);

        $subject = new GroupSubjectMatcher('cn=admins,dc=foo,dc=bar');
        $subject->setBackend($this->mockBackend);

        self::assertTrue($subject->matches(
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            $this->targetDn,
        ));
    }

    public function test_it_should_not_match_when_dn_is_different_after_normalization(): void
    {
        $groupEntry = Entry::create(
            'cn=admins,dc=foo,dc=bar',
            ['member' => ['cn=other,dc=foo,dc=bar']],
        );

        $this->mockBackend
            ->method('get')
            ->willReturn($groupEntry);

        $subject = new GroupSubjectMatcher('cn=admins,dc=foo,dc=bar');
        $subject->setBackend($this->mockBackend);

        self::assertFalse($subject->matches(
            BindToken::fromDn(
                'cn=admin, dc=foo, dc=bar',
            ),
            $this->targetDn,
        ));
    }

    public function test_it_should_evict_oldest_entry_when_cache_is_full(): void
    {
        $groupEntry = Entry::create(
            'cn=admins,dc=foo,dc=bar',
            ['member' => ['cn=admin,dc=foo,dc=bar']],
        );

        $this->mockBackend
            ->expects(self::exactly(4))
            ->method('get')
            ->willReturn($groupEntry);

        $subject = new GroupSubjectMatcher(
            'cn=admins,dc=foo,dc=bar',
            'member',
            2,
        );
        $subject->setBackend($this->mockBackend);

        $token1 = BindToken::fromDn('cn=admin,dc=foo,dc=bar');
        $token2 = BindToken::fromDn('cn=admin,dc=foo,dc=bar');
        $token3 = BindToken::fromDn('cn=admin,dc=foo,dc=bar');

        $subject->matches($token1, $this->targetDn);
        $subject->matches($token2, $this->targetDn);
        $subject->matches($token3, $this->targetDn);
        $subject->matches($token2, $this->targetDn);
        $subject->matches($token1, $this->targetDn);
    }
}
