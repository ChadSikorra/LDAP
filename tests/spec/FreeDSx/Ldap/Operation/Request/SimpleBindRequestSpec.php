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
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use PhpSpec\ObjectBehavior;

class SimpleBindRequestSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith('', '');
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(SimpleBindRequest::class);
    }

    public function it_should_extend_bind_request(): void
    {
        $this->shouldBeAnInstanceOf(BindRequest::class);
    }

    public function it_should_default_to_ldap_v3(): void
    {
        $this->getVersion()->shouldBeEqualTo(3);
    }

    public function it_should_set_the_username(): void
    {
        $this->setUsername('foo');
        $this->getUsername()->shouldBeEqualTo('foo');
    }

    public function it_should_set_the_password(): void
    {
        $this->setPassword('bar');
        $this->getPassword()->shouldBeEqualTo('bar');
    }

    public function it_should_not_allow_an_empty_username_or_password(): void
    {
        $this->shouldThrow(BindException::class)->duringToAsn1();

        $this->setUsername('foo');
        $this->shouldThrow(BindException::class)->duringToAsn1();

        $this->setUsername('');
        $this->setPassword('bar');
        $this->shouldThrow(BindException::class)->duringToAsn1();

        $this->setUsername('foo')->setPassword('bar');
        $this->shouldNotThrow(BindException::class)->duringToAsn1();
    }

    public function it_should_correctly_detect_a_zero_string_as_non_empty(): void
    {
        $this->setUsername('foo');
        $this->setPassword('0');

        $this->shouldNotThrow(BindException::class)->duringToAsn1();

        $this->setUsername('0');
        $this->shouldNotThrow(BindException::class)->duringToAsn1();
    }

    public function it_should_generate_correct_asn1(): void
    {
        $this->setUsername('foo')->setPassword('bar');

        $this->toAsn1()->shouldBeLike(Asn1::application(0, Asn1::sequence(
            Asn1::integer(3),
            Asn1::octetString('foo'),
            Asn1::context(0, Asn1::octetString('bar'))
        )));
    }

    public function it_should_be_constructed_from_asn1(): void
    {
        $bind = new SimpleBindRequest('foo', 'bar');

        $this::fromAsn1($bind->toAsn1())->shouldBeLike($bind);
    }

    public function it_should_not_be_constructed_from_invalid_asn1(): void
    {
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::octetString('foo')]);
        $this->shouldThrow(ProtocolException::class)->during('fromAsn1', [Asn1::sequence(
            Asn1::octetString('foo'),
            Asn1::integer(3)
        )]);
    }
}
