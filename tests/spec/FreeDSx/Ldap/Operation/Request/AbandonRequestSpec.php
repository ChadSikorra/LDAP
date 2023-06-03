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

namespace spec\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use PhpSpec\ObjectBehavior;

class AbandonRequestSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(1);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(AbandonRequest::class);
    }

    public function it_should_get_the_message_id(): void
    {
        $this->getMessageId()->shouldBeEqualTo(1);
        $this->setMessageId(2)->getMessageId()->shouldBeEqualTo(2);
    }

    public function it_should_generate_correct_ASN1(): void
    {
        $this->toAsn1()->shouldBeLike(Asn1::application(16, Asn1::integer(1)));
    }

    public function it_should_be_constructed_from_ASN1(): void
    {
        $this::fromAsn1(Asn1::application(16, Asn1::integer(1)))
            ->shouldBeLike(new AbandonRequest(1));
    }

    public function it_should_not_allow_non_integers_from_ASN1(): void
    {
        $this->shouldThrow(ProtocolException::class)
            ->during(
                'fromAsn1',
                [
                    Asn1::application(
                        16,
                        Asn1::octetString('foo')
                    )
                ]
            );
    }
}
