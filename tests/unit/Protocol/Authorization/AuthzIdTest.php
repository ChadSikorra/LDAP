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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Authorization;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Protocol\Authorization\AuthzIdType;
use PHPUnit\Framework\TestCase;

final class AuthzIdTest extends TestCase
{
    public function test_it_parses_the_dn_form(): void
    {
        $authzId = AuthzId::fromString('dn:cn=foo,dc=example,dc=com');

        self::assertTrue($authzId->isType(AuthzIdType::Dn));
        self::assertSame(
            'cn=foo,dc=example,dc=com',
            $authzId->getValue(),
        );
        self::assertSame(
            'dn:cn=foo,dc=example,dc=com',
            $authzId->toString(),
        );
    }

    public function test_it_parses_the_username_form(): void
    {
        $authzId = AuthzId::fromString('u:bob');

        self::assertTrue($authzId->isType(AuthzIdType::Username));
        self::assertSame(
            'bob',
            $authzId->getValue(),
        );
        self::assertSame(
            'u:bob',
            $authzId->toString(),
        );
    }

    public function test_an_empty_string_is_the_anonymous_identity(): void
    {
        $authzId = AuthzId::fromString('');

        self::assertTrue($authzId->isType(AuthzIdType::Anonymous));
        self::assertSame(
            '',
            $authzId->getValue(),
        );
        self::assertSame(
            '',
            $authzId->toString(),
        );
    }

    public function test_it_rejects_an_unrecognized_form(): void
    {
        $this->expectException(InvalidArgumentException::class);

        AuthzId::fromString('bob');
    }

    public function test_it_builds_from_a_dn(): void
    {
        $authzId = AuthzId::fromDn(new Dn('cn=foo,dc=example,dc=com'));

        self::assertTrue($authzId->isType(AuthzIdType::Dn));
        self::assertSame(
            'dn:cn=foo,dc=example,dc=com',
            $authzId->toString(),
        );
    }

    public function test_it_builds_from_a_username(): void
    {
        $authzId = AuthzId::fromUsername('bob');

        self::assertTrue($authzId->isType(AuthzIdType::Username));
        self::assertSame(
            'bob',
            $authzId->getValue(),
        );
        self::assertSame(
            'u:bob',
            $authzId->toString(),
        );
    }
}
