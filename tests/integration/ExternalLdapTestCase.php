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

namespace Tests\Integration\FreeDSx\Ldap;

/**
 * Base for tests that require a real external LDAP server (OpenLDAP / AD).
 */
class ExternalLdapTestCase extends LdapTestCase
{
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (getenv('LDAP_TESTS_ENABLED') !== '1') {
            static::markTestSkipped('OpenLDAP integration tests are disabled. Set LDAP_TESTS_ENABLED=1 to enable.');
        }
    }
}
