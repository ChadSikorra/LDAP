<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Control\ReadEntry;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ReadEntry\PostReadResponseControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadResponseControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

final class ReadEntryResponseControlTest extends TestCase
{
    public function test_pre_read_response_has_the_pre_read_oid(): void
    {
        self::assertSame(
            Control::OID_PRE_READ,
            (new PreReadResponseControl(Entry::fromArray('cn=foo,dc=ex,dc=com')))->getTypeOid(),
        );
    }

    public function test_post_read_response_has_the_post_read_oid(): void
    {
        self::assertSame(
            Control::OID_POST_READ,
            (new PostReadResponseControl(Entry::fromArray('cn=foo,dc=ex,dc=com')))->getTypeOid(),
        );
    }

    public function test_it_exposes_the_entry(): void
    {
        $entry = Entry::fromArray('cn=foo,dc=ex,dc=com', ['cn' => ['foo']]);

        self::assertSame(
            $entry,
            (new PreReadResponseControl($entry))->getEntry(),
        );
    }

    public function test_it_round_trips_the_entry_through_asn1(): void
    {
        $encoder = new LdapEncoder();
        $control = new PostReadResponseControl(Entry::fromArray(
            'cn=foo,dc=ex,dc=com',
            [
                'cn' => ['foo'],
                'sn' => ['bar', 'baz'],
            ],
        ));

        $decoded = PostReadResponseControl::fromAsn1(
            $encoder->decode($encoder->encode($control->toAsn1())),
        );

        self::assertSame(
            'cn=foo,dc=ex,dc=com',
            $decoded->getEntry()->getDn()->toString(),
        );
        self::assertSame(
            ['foo'],
            $decoded->getEntry()->get('cn')?->getValues(),
        );
        self::assertSame(
            ['bar', 'baz'],
            $decoded->getEntry()->get('sn')?->getValues(),
        );
        self::assertSame(
            Control::OID_POST_READ,
            $decoded->getTypeOid(),
        );
    }
}
