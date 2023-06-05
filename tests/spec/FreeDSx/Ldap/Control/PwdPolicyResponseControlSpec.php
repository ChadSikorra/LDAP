<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Control;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PhpSpec\ObjectBehavior;

class PwdPolicyResponseControlSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(1, 2, 3);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(PwdPolicyResponseControl::class);
    }

    public function it_should_get_the_error(): void
    {
        $this->getError()->shouldBeEqualTo(3);
    }

    public function it_should_get_the_time_before_expiration(): void
    {
        $this->getTimeBeforeExpiration()->shouldBeEqualTo(1);
    }

    public function it_should_get_the_grace_attempts_remaining(): void
    {
        $this->getGraceAttemptsRemaining()->shouldBeEqualTo(2);
    }

    public function it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        $this->beConstructedThrough('fromAsn1', [Asn1::sequence(
            Asn1::octetString(Control::OID_PWD_POLICY),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::context(0, Asn1::sequence(Asn1::context(0, Asn1::integer(100)))),
                Asn1::context(1, Asn1::enumerated(2))
            )))
        )]);

        $this->getTimeBeforeExpiration()->shouldBeEqualTo(100);
        $this->getError()->shouldBeEqualTo(2);
        $this->getTypeOid()->shouldBeEqualTo(Control::OID_PWD_POLICY);
        $this->getCriticality()->shouldBeEqualTo(false);
    }

    public function it_should_generate_correct_asn1(): void
    {
        $this->beConstructedWith(100, null, 2);

        $encoder = new LdapEncoder();
        $this->toAsn1()->shouldBeLike(
            Asn1::sequence(
                Asn1::octetString(Control::OID_PWD_POLICY),
                Asn1::boolean(false),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::context(0, Asn1::sequence(Asn1::context(0, Asn1::integer(100)))),
                    Asn1::context(1, Asn1::enumerated(2))
                )))
            )
        );
    }
}
