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

namespace Tests\Unit\FreeDSx\Ldap\Server\AccessControl\Target;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\AccessControl\Target\SubtreeTargetMatcher;
use PHPUnit\Framework\TestCase;

final class SubtreeTargetMatcherTest extends TestCase
{
    public function test_it_should_match_descendant_dn(): void
    {
        $subject = new SubtreeTargetMatcher('dc=foo,dc=bar');

        self::assertTrue($subject->matches(new Dn('cn=admin,dc=foo,dc=bar')));
    }

    public function test_it_should_match_deeply_nested_descendant(): void
    {
        $subject = new SubtreeTargetMatcher('dc=foo,dc=bar');

        self::assertTrue($subject->matches(new Dn('uid=user,ou=people,dc=foo,dc=bar')));
    }

    public function test_it_should_match_root_dn_of_subtree_itself(): void
    {
        $subject = new SubtreeTargetMatcher('dc=foo,dc=bar');

        // isDescendantOf uses inclusive subtree semantics — the root matches itself.
        self::assertTrue($subject->matches(new Dn('dc=foo,dc=bar')));
    }

    public function test_it_should_not_match_sibling_subtree(): void
    {
        $subject = new SubtreeTargetMatcher('dc=foo,dc=bar');

        self::assertFalse($subject->matches(new Dn('cn=admin,dc=other,dc=bar')));
    }
}
