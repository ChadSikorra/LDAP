<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Entry;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Option;
use FreeDSx\Ldap\Entry\Options;
use PhpSpec\ObjectBehavior;

class AttributeSpec extends ObjectBehavior
{
    public function let()
    {
        $this->beConstructedWith('cn', 'foo', 'bar');
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(Attribute::class);
    }

    public function it_should_implement_countable()
    {
        $this->shouldImplement('\Countable');
    }

    public function it_should_implement_iterator_aggregate()
    {
        $this->shouldImplement('\IteratorAggregate');
    }

    public function it_should_get_the_name()
    {
        $this->getName()->shouldBeEqualTo('cn');
        $this->getOptions()->add('foo');
        $this->getName()->shouldBeEqualTo('cn');
    }

    public function it_should_get_the_complete_attribute_description()
    {
        $this->getDescription()->shouldBeEqualTo('cn');
        $this->getOptions()->add('foo');
        $this->getDescription()->shouldBeEqualTo('cn;foo');
    }

    public function it_should_return_false_for_hasOptions_when_there_are_none()
    {
        $this->hasOptions()->shouldBeEqualTo(false);
    }

    public function it_should_get_options()
    {
        $this->getOptions()->shouldBeLike(new Options());
    }
    
    public function it_should_get_the_values()
    {
        $this->getValues()->shouldBeEqualTo(['foo', 'bar']);
    }

    public function it_should_get_the_first_value_if_it_exists()
    {
        $this->firstValue()->shouldBeEqualTo('foo');
    }

    public function it_should_get_the_last_value_if_it_exists()
    {
        $this->lastValue()->shouldBeEqualTo('bar');
    }

    public function it_should_get_null_if_the_first_value_does_not_exist()
    {
        $this->beConstructedWith('foo');

        $this->firstValue()->shouldBeNull();
    }

    public function it_should_get_null_if_the_last_value_does_not_exist()
    {
        $this->beConstructedWith('foo');

        $this->lastValue()->shouldBeNull();
    }

    public function it_should_have_a_string_representation()
    {
        $this->__toString()->shouldBeEqualTo('foo, bar');
    }

    public function it_should_get_a_count_of_values()
    {
        $this->count()->shouldBeEqualTo(2);
    }

    public function it_should_add_values()
    {
        $this->add('foobar', 'meh');

        $this->getValues()->shouldBeEqualTo(['foo', 'bar', 'foobar', 'meh']);
    }

    public function it_should_remove_values()
    {
        $this->remove('bar');

        $this->getValues()->shouldBeEqualTo(['foo']);
    }

    public function it_should_set_values()
    {
        $this->set('foo')->getValues()->shouldBeEqualTo(['foo']);
    }

    public function it_should_reset_values()
    {
        $this->reset()->getValues()->shouldBeEqualTo([]);
    }

    public function it_should_check_if_a_value_exists()
    {
        $this->has('foo')->shouldBeEqualTo(true);
        $this->has('bleh')->shouldBeEqualTo(false);
    }

    public function it_should_check_if_it_equals_another_attribute()
    {
        $this->equals(new Attribute('cn'))->shouldBeEqualTo(true);
        $this->equals(new Attribute('CN'))->shouldBeEqualTo(true);
        $this->equals(new Attribute('foo'))->shouldBeEqualTo(false);
    }

    public function it_should_check_if_it_equals_another_attribute_with_options()
    {
        $this->equals(new Attribute('cn;foo'))->shouldBeEqualTo(false);
        $this->getOptions()->add('foo');
        $this->equals(new Attribute('cn;foo'))->shouldBeEqualTo(true);
    }
    
    public function it_should_be_check_equality_with_the_name_only_by_default()
    {
        $this->getOptions()->add('foo');

        $this->equals(new Attribute('cn'))->shouldBeEqualTo(true);
    }

    public function it_should_be_check_equality_with_name_and_options_when_strict_is_set()
    {
        $this->getOptions()->add('foo');

        $this->equals(new Attribute('cn'), true)->shouldBeEqualTo(false);
    }
    
    public function it_should_escape_a_value()
    {
        $this::escape("(foo=*\bar)\x00")->shouldBeEqualTo('\28foo=\2a\5cbar\29\00');
    }

    public function it_should_escape_a_value_to_complete_hex()
    {
        $this::escapeAll("foobar")->shouldBeEqualTo('\66\6f\6f\62\61\72');
    }

    public function it_should_ignore_an_empty_value_when_escaping()
    {
        $this::escape('')->shouldBeLike('');
    }

    public function it_should_not_escape_a_string_that_is_already_hex_encoded()
    {
        $this::escape('\66\6f\6f\62\61\72')->shouldBeEqualTo('\66\6f\6f\62\61\72');
    }

    public function it_should_parse_options_in_the_attribute()
    {
        $this->beConstructedWith('foo;lang-en-us', 'bar');
        
        $this->getName()->shouldBeEqualTo('foo');
        $this->getOptions()->shouldBeLike(new Options(new Option('lang-en-us')));
    }
}
