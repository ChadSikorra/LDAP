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
use FreeDSx\Ldap\Server\AccessControl\Subject\DnSubtreeSubjectMatcher;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;

final class DnSubtreeSubjectMatcherTest extends TestCase
{
    private Dn $targetDn;

    protected function setUp(): void
    {
        $this->targetDn = new Dn('dc=foo,dc=bar');
    }

    public function test_it_should_match_when_bound_dn_is_within_subtree(): void
    {
        $subject = new DnSubtreeSubjectMatcher('dc=foo,dc=bar');

        self::assertTrue($subject->matches(
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            $this->targetDn,
        ));
    }

    public function test_it_should_not_match_when_bound_dn_is_in_sibling_subtree(): void
    {
        $subject = new DnSubtreeSubjectMatcher('dc=foo,dc=bar');

        self::assertFalse($subject->matches(
            BindToken::fromDn(
                'cn=admin,dc=other,dc=bar',
            ),
            $this->targetDn,
        ));
    }

    public function test_it_should_not_match_for_anonymous_token(): void
    {
        $subject = new DnSubtreeSubjectMatcher('dc=foo,dc=bar');

        self::assertFalse($subject->matches(
            new AnonToken(),
            $this->targetDn,
        ));
    }

    public function test_it_should_not_match_for_anonymous_token_even_with_dn_in_subtree(): void
    {
        $subject = new DnSubtreeSubjectMatcher('dc=foo,dc=bar');

        self::assertFalse($subject->matches(
            new AnonToken('cn=admin,dc=foo,dc=bar'),
            $this->targetDn,
        ));
    }

    public function test_it_should_not_match_and_not_throw_when_resolved_dn_is_not_valid(): void
    {
        $subject = new DnSubtreeSubjectMatcher('dc=foo,dc=bar');

        self::assertFalse($subject->matches(
            BindToken::fromDn(
                'jdoe',
            ),
            $this->targetDn,
        ));
    }
}
