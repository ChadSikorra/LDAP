<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Control\Ad;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Ad\SdFlagsControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PhpSpec\ObjectBehavior;

class SdFlagsControlSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(SdFlagsControl::DACL_SECURITY_INFORMATION);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(SdFlagsControl::class);
    }

    public function it_should_get_the_flags(): void
    {
        $this->getFlags()->shouldBeEqualTo(SdFlagsControl::DACL_SECURITY_INFORMATION);
    }

    public function it_should_set_the_flags(): void
    {
        $this->setFlags(SdFlagsControl::SACL_SECURITY_INFORMATION)->getFlags()->shouldBeEqualTo(SdFlagsControl::SACL_SECURITY_INFORMATION);
    }

    public function it_should_generate_correct_ASN1(): void
    {
        $encoder = new LdapEncoder();

        $this->toAsn1()->shouldBeLike(Asn1::sequence(
            Asn1::octetString(Control::OID_SD_FLAGS),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::integer(4)
            )))
        ));
    }
}
