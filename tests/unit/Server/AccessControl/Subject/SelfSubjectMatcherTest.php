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
use FreeDSx\Ldap\Server\AccessControl\Subject\SelfSubjectMatcher;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;

final class SelfSubjectMatcherTest extends TestCase
{
    private SelfSubjectMatcher $subject;

    protected function setUp(): void
    {
        $this->subject = new SelfSubjectMatcher();
    }

    public function test_it_should_match_when_username_equals_target_dn(): void
    {
        self::assertTrue($this->subject->matches(
            BindToken::fromDn(
                'cn=foo,dc=bar',
            ),
            new Dn('cn=foo,dc=bar'),
        ));
    }

    public function test_it_should_match_case_insensitively(): void
    {
        self::assertTrue($this->subject->matches(
            BindToken::fromDn(
                'CN=Foo,DC=bar',
            ),
            new Dn('cn=foo,dc=bar'),
        ));
    }

    public function test_it_should_not_match_when_username_differs_from_target_dn(): void
    {
        self::assertFalse($this->subject->matches(
            BindToken::fromDn(
                'cn=admin,dc=bar',
            ),
            new Dn('cn=foo,dc=bar'),
        ));
    }

    public function test_it_should_not_match_for_anonymous_token(): void
    {
        self::assertFalse($this->subject->matches(
            new AnonToken(),
            new Dn('cn=foo,dc=bar'),
        ));
    }

    public function test_it_should_not_match_for_anonymous_token_even_with_matching_dn(): void
    {
        self::assertFalse($this->subject->matches(
            new AnonToken('cn=foo,dc=bar'),
            new Dn('cn=foo,dc=bar'),
        ));
    }
}
