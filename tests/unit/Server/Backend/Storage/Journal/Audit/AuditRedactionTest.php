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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit\AuditRedaction;
use PHPUnit\Framework\TestCase;

final class AuditRedactionTest extends TestCase
{
    public function test_it_drops_excluded_attributes_case_insensitively(): void
    {
        $redaction = new AuditRedaction(['userPassword']);
        $entry = new Entry(
            new Dn('cn=a,dc=example,dc=com'),
            new Attribute('cn', 'a'),
            new Attribute('UserPassword', 'secret'),
        );

        $result = $redaction->apply($entry);

        self::assertSame(
            ['cn' => ['a']],
            $result,
        );
    }

    public function test_the_default_drops_password_bearing_attributes(): void
    {
        $entry = new Entry(
            new Dn('cn=a,dc=example,dc=com'),
            new Attribute('cn', 'a'),
            new Attribute('userPassword', 'secret'),
            new Attribute('pwdHistory', '20250515120000Z#1.3.6#6#secret'),
        );

        $result = AuditRedaction::default()->apply($entry);

        self::assertSame(
            ['cn' => ['a']],
            $result,
        );
    }

    public function test_an_excluded_attribute_carrying_an_option_is_still_dropped(): void
    {
        $redaction = new AuditRedaction(['userPassword']);
        $entry = new Entry(
            new Dn('cn=a,dc=example,dc=com'),
            new Attribute('cn', 'a'),
            new Attribute('userPassword;binary', 'secret'),
        );

        $result = $redaction->apply($entry);

        self::assertSame(
            ['cn' => ['a']],
            $result,
        );
    }

    public function test_a_retained_attribute_keeps_its_options_in_the_key(): void
    {
        $redaction = new AuditRedaction(['userPassword']);
        $entry = new Entry(
            new Dn('cn=a,dc=example,dc=com'),
            new Attribute('cn;lang-en', 'a'),
        );

        $result = $redaction->apply($entry);

        self::assertSame(
            ['cn;lang-en' => ['a']],
            $result,
        );
    }
}
