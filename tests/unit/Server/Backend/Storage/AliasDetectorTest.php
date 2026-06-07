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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\AliasDetector;
use PHPUnit\Framework\TestCase;

final class AliasDetectorTest extends TestCase
{
    public function test_it_detects_an_alias_entry(): void
    {
        $entry = new Entry(
            new Dn('cn=ref,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'alias'),
            new Attribute('aliasedObjectName', 'cn=real,dc=example,dc=com'),
        );

        self::assertTrue(AliasDetector::isAlias($entry));
    }

    public function test_it_matches_object_class_case_insensitively(): void
    {
        $entry = new Entry(
            new Dn('cn=ref,dc=example,dc=com'),
            new Attribute('objectClass', 'ALIAS'),
        );

        self::assertTrue(AliasDetector::isAlias($entry));
    }

    public function test_it_returns_false_for_a_non_alias_entry(): void
    {
        $entry = new Entry(
            new Dn('cn=real,dc=example,dc=com'),
            new Attribute('objectClass', 'inetOrgPerson'),
        );

        self::assertFalse(AliasDetector::isAlias($entry));
    }

    public function test_it_returns_false_when_object_class_is_absent(): void
    {
        $entry = new Entry(new Dn('cn=real,dc=example,dc=com'));

        self::assertFalse(AliasDetector::isAlias($entry));
    }
}
