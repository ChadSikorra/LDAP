<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\DnRequestInterface;
use PhpSpec\ObjectBehavior;

class DeleteRequestSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith('cn=foo,dc=foo,dc=bar');
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(DeleteRequest::class);
    }

    public function it_should_implement_the_DnRequestInterface(): void
    {
        $this->shouldImplement(DnRequestInterface::class);
    }

    public function it_should_set_the_dn(): void
    {
        $this->getDn()->shouldBeLike(new Dn('cn=foo,dc=foo,dc=bar'));
        $this->setDn(new Dn('foo'))->getDn()->shouldBeLike(new Dn('foo'));
    }

    public function it_should_generate_correct_asn1(): void
    {
        $this->toAsn1()->shouldBeLike(Asn1::application(10, Asn1::octetString('cn=foo,dc=foo,dc=bar')));
    }

    public function it_should_be_constructed_from_asn1(): void
    {
        $this->beConstructedThrough('fromAsn1', [Asn1::application(10, Asn1::octetString(
            'dc=foo,dc=bar'
        ))]);

        $this->getDn()->shouldBeLike(new Dn('dc=foo,dc=bar'));
    }

    public function it_should_not_be_constructed_from_invalid_asn1(): void
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::application(11, Asn1::octetString(
            'dc=foo,dc=bar'
        ))]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::application(11, Asn1::integer(
            2
        ))]);
    }
}
