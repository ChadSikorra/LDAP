<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Search\Filter;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use PhpSpec\ObjectBehavior;

class EqualityFilterSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith('foo', 'bar');
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(EqualityFilter::class);
    }

    public function it_should_implement_fiter_interface(): void
    {
        $this->shouldImplement(FilterInterface::class);
    }

    public function it_should_get_the_attribute_name(): void
    {
        $this->getAttribute()->shouldBeEqualTo('foo');
        $this->setAttribute('foobar')->getAttribute()->shouldBeEqualTo('foobar');
    }

    public function it_should_get_the_value(): void
    {
        $this->getValue()->shouldBeEqualTo('bar');
    }

    public function it_should_generate_correct_asn1(): void
    {
        $this->toAsn1()->shouldBeLike(Asn1::context(3, Asn1::sequence(
            Asn1::octetString('foo'),
            Asn1::octetString('bar')
        )));
    }

    public function it_should_be_constructed_from_asn1(): void
    {
        $this::fromAsn1((new EqualityFilter('foo', 'bar'))->toAsn1())->shouldBeLike(new EqualityFilter('foo', 'bar'));
    }

    public function it_should_get_the_string_filter_representation(): void
    {
        $this->toString()->shouldBeEqualTo('(foo=bar)');
    }

    public function it_should_have_a_filter_as_a_toString_representation(): void
    {
        $this->__toString()->shouldBeEqualTo('(foo=bar)');
    }

    public function it_should_escape_values_on_the_string_representation(): void
    {
        $this->beConstructedWith('foo', ')(bar=foo');
        $this->toString()->shouldBeEqualTo('(foo=\29\28bar=foo)');
    }
}
