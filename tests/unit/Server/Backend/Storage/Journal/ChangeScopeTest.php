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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Journal;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeScope;
use PHPUnit\Framework\TestCase;

final class ChangeScopeTest extends TestCase
{
    private Dn $base;

    protected function setUp(): void
    {
        $this->base = new Dn('dc=example,dc=com');
    }

    public function test_whole_subtree_contains_the_base_and_all_descendants(): void
    {
        $scope = ChangeScope::wholeSubtree($this->base);

        self::assertTrue($scope->contains(new Dn('dc=example,dc=com')));
        self::assertTrue($scope->contains(new Dn('cn=a,dc=example,dc=com')));
        self::assertTrue($scope->contains(new Dn('cn=x,ou=people,dc=example,dc=com')));
        self::assertFalse($scope->contains(new Dn('dc=other,dc=com')));
    }

    public function test_one_level_contains_only_direct_children(): void
    {
        $scope = ChangeScope::oneLevel($this->base);

        self::assertTrue($scope->contains(new Dn('cn=a,dc=example,dc=com')));
        self::assertFalse($scope->contains(new Dn('dc=example,dc=com')));
        self::assertFalse($scope->contains(new Dn('cn=x,ou=people,dc=example,dc=com')));
    }

    public function test_base_object_contains_only_the_base(): void
    {
        $scope = ChangeScope::baseObject($this->base);

        self::assertTrue($scope->contains(new Dn('dc=example,dc=com')));
        self::assertFalse($scope->contains(new Dn('cn=a,dc=example,dc=com')));
    }

    public function test_base_object_match_is_case_insensitive(): void
    {
        $scope = ChangeScope::baseObject($this->base);

        self::assertTrue($scope->contains(new Dn('DC=Example,DC=Com')));
    }
}
