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
use FreeDSx\Ldap\Server\AccessControl\Subject\AuthenticatedSubjectMatcher;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;

final class AuthenticatedSubjectMatcherTest extends TestCase
{
    private AuthenticatedSubjectMatcher $subject;

    private Dn $dn;

    protected function setUp(): void
    {
        $this->subject = new AuthenticatedSubjectMatcher();
        $this->dn = new Dn('dc=foo,dc=bar');
    }

    public function test_it_should_match_bind_token(): void
    {
        self::assertTrue($this->subject->matches(
            BindToken::fromDn(
                'cn=admin,dc=foo,dc=bar',
            ),
            $this->dn,
        ));
    }

    public function test_it_should_match_any_authenticated_token_interface_implementation(): void
    {
        $token = $this->createMock(AuthenticatedTokenInterface::class);

        self::assertTrue($this->subject->matches(
            $token,
            $this->dn,
        ));
    }

    public function test_it_should_not_match_anonymous_token(): void
    {
        self::assertFalse($this->subject->matches(
            new AnonToken(),
            $this->dn,
        ));
    }
}
