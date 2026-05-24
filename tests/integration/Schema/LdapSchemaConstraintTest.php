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

namespace Tests\Integration\FreeDSx\Ldap\Schema;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * End-to-end rejection of malformed values and conflicting structural classes under Strict validation.
 */
final class LdapSchemaConstraintTest extends ServerTestCase
{
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-backend-storage',
            'tcp',
            ['--validation-mode=strict'],
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-backend-storage');

        parent::setUp();
    }

    public function test_add_with_invalid_attribute_syntax_is_rejected(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=bad-syntax,dc=foo,dc=bar',
            [
                'cn' => 'bad-syntax',
                'sn' => 'Smith',
                'objectClass' => 'person',
                'seeAlso' => 'not a dn',
            ],
        ));
    }

    public function test_add_with_two_unrelated_structural_classes_is_rejected(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=two-structural,dc=foo,dc=bar',
            [
                'cn' => 'two-structural',
                'sn' => 'Smith',
                'ou' => 'People',
                'objectClass' => ['person', 'organizationalUnit'],
            ],
        ));
    }
}
