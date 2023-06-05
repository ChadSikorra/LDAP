<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Control\Vlv;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Vlv\VlvControl;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PhpSpec\ObjectBehavior;

class VlvControlSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(10, 9, 8, 0);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(VlvControl::class);
    }

    public function it_should_have_a_count_of_zero_by_default(): void
    {
        $this->getCount()->shouldBeEqualTo(0);
    }

    public function it_should_get_and_set_the_value_for_after(): void
    {
        $this->getAfter()->shouldBeEqualTo(9);
        $this->setBefore(10)->getBefore()->shouldBeEqualTo(10);
    }

    public function it_should_get_and_set_the_value_for_before(): void
    {
        $this->getBefore()->shouldBeEqualTo(10);
        $this->setBefore(20)->getBefore()->shouldBeEqualTo(20);
    }

    public function it_should_get_and_set_the_value_for_the_offset(): void
    {
        $this->getOffset()->shouldBeEqualTo(8);
        $this->setOffset(16)->getOffset()->shouldBeEqualTo(16);
    }

    public function it_should_generate_correct_asn1(): void
    {
        $encoder = new LdapEncoder();
        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::octetString(Control::OID_VLV),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::integer(10),
                Asn1::integer(9),
                Asn1::context(0, Asn1::sequence(
                    Asn1::integer(8),
                    Asn1::integer(0)
                ))
            )))
        ));
    }
}
