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
use FreeDSx\Ldap\Search\Filter\NotFilter;
use FreeDSx\Ldap\Search\Filters;
use PhpSpec\ObjectBehavior;

class NotFilterSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(Filters::equal('foo', 'bar'));
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(NotFilter::class);
    }

    public function it_should_set_the_filter(): void
    {
        $this->set(Filters::gte('foobar', 'foo'));
        $this->get()->shouldBeLike(Filters::gte('foobar', 'foo'));
    }

    public function it_should_generate_correct_asn1(): void
    {
        $this->toAsn1()->shouldBeLike(Asn1::context(2, Asn1::sequence(Filters::equal('foo', 'bar')->toAsn1())));
    }

    public function it_should_be_constructed_from_asn1(): void
    {
        $this::fromAsn1((new NotFilter(Filters::equal('foo', 'bar')))->toAsn1())->shouldBeLike(
            new NotFilter(new EqualityFilter('foo', 'bar'))
        );
    }

    public function it_should_get_the_string_filter_representation(): void
    {
        $this->toString()->shouldBeEqualTo('(!(foo=bar))');
    }

    public function it_should_have_a_filter_as_a_toString_representation(): void
    {
        $this->__toString()->shouldBeEqualTo('(!(foo=bar))');
    }

    public function it_should_escape_values_on_the_string_representation(): void
    {
        $this->beConstructedWith(Filters::equal('foo', '*bar'));
        $this->toString()->shouldBeEqualTo('(!(foo=\2abar))');
    }
}
