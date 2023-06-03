<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Operation\Response;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PhpSpec\ObjectBehavior;

class PasswordModifyResponseSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(new LdapResult(0, 'foo'), '12345');
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(PasswordModifyResponse::class);
    }

    public function it_should_get_the_result_code(): void
    {
        $this->getResultCode()->shouldBeEqualTo(0);
    }

    public function it_should_get_the_dn(): void
    {
        $this->getDn()->shouldBeLike(new Dn('foo'));
    }

    public function it_should_get_the_generated_password(): void
    {
        $this->getGeneratedPassword()->shouldBeEqualTo('12345');
    }

    public function it_should_be_constructed_from_asn1_with_a_generated_password(): void
    {
        $encoder = new LdapEncoder();

        $this->beConstructedThrough('fromAsn1', [Asn1::application(24, Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::octetString('dc=foo,dc=bar'),
            Asn1::octetString('foo'),
            Asn1::context(3, (new IncompleteType(
                $encoder->encode(Asn1::octetString('ldap://foo'))
                . $encoder->encode(Asn1::octetString('ldap://bar'))
            ))->setIsConstructed(true)),
            Asn1::context(11, Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::context(0, Asn1::octetString('bleep-blorp'))
            ))))
        ))]);

        $this->getGeneratedPassword()->shouldBeEqualTo('bleep-blorp');
        $this->getResultCode()->shouldBeEqualTo(0);
        $this->getDn()->shouldBeLike(new Dn('dc=foo,dc=bar'));
    }

    public function it_should_be_constructed_from_asn1_without_a_generated_password(): void
    {
        $encoder = new LdapEncoder();

        $this->beConstructedThrough('fromAsn1', [Asn1::application(24, Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::octetString('dc=foo,dc=bar'),
            Asn1::octetString('foo'),
            Asn1::context(3, (new IncompleteType(
                $encoder->encode(Asn1::octetString('ldap://foo'))
                . $encoder->encode(Asn1::octetString('ldap://bar'))
            ))->setIsConstructed(true)),
            Asn1::context(11, Asn1::octetString($encoder->encode(Asn1::sequence())))
        ))]);

        $this->getGeneratedPassword()->shouldBeNull();
    }
}
