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
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PhpSpec\ObjectBehavior;

class CancelRequestSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(1);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(CancelRequest::class);
    }

    public function it_should_set_the_message_id(): void
    {
        $this->getMessageId()->shouldBeEqualTo(1);
        $this->setMessageId(2)->getMessageId()->shouldBeEqualTo(2);
    }

    public function it_should_generate_correct_asn1(): void
    {
        $encoder = new LdapEncoder();

        $this->toAsn1()->shouldBeLike(Asn1::application(23, Asn1::sequence(
            Asn1::context(0, Asn1::octetString(ExtendedRequest::OID_CANCEL)),
            Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::integer(1)
            ))))
        )));
    }

    public function it_should_be_constructed_from_asn1(): void
    {
        $this::fromAsn1((new CancelRequest(2))->toAsn1())->shouldBeLike(new CancelRequest(2));
    }

    public function it_should_detect_invalid_asn1_from_asn1(): void
    {
        $req = new ExtendedRequest('foo', Asn1::octetString('foo'));
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [$req->toAsn1()]);

        $req->setValue(Asn1::sequence());
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [$req->toAsn1()]);

        $req->setValue(Asn1::sequence(Asn1::octetString('bar')));
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [$req->toAsn1()]);
    }
}
