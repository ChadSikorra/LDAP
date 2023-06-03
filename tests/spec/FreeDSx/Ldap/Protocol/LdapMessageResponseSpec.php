<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use PhpSpec\ObjectBehavior;

class LdapMessageResponseSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(1, new SearchResponse(new SearchResultDone(0, 'dc=foo,dc=bar', ''), new Entries()), new Control('foo'));
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(LdapMessageResponse::class);
    }

    public function it_should_get_the_response(): void
    {
        $this->getResponse()->shouldBeAnInstanceOf(SearchResponse::class);
    }

    public function it_should_get_the_controls(): void
    {
        $this->controls()->has('foo')->shouldBeEqualTo(true);
    }

    public function it_should_get_the_message_id(): void
    {
        $this->getMessageId()->shouldBeEqualTo(1);
    }

    public function it_should_be_constructed_from_ASN1(): void
    {
        $encoder = new LdapEncoder();

        $this->beConstructedThrough('fromAsn1', [Asn1::sequence(
            Asn1::integer(3),
            Asn1::application(11, Asn1::sequence(
                Asn1::integer(0),
                Asn1::octetString('dc=foo,dc=bar'),
                Asn1::octetString('')
            )),
            Asn1::context(0, (new IncompleteType($encoder->encode((new Control('foo'))->toAsn1())))->setIsConstructed(true))
        )]);

        $this->getMessageId()->shouldBeEqualTo(3);
        $this->getResponse()->shouldBeLike(new DeleteResponse(0, 'dc=foo,dc=bar', ''));
        $this->controls()->has('foo')->shouldBeEqualTo(true);
    }
}
