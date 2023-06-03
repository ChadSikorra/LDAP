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

namespace spec\FreeDSx\Ldap\Entry;

use FreeDSx\Ldap\Entry\Option;
use PhpSpec\ObjectBehavior;

class OptionSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith('foo');
    }
    
    public function it_is_initializable(): void
    {
        $this->shouldHaveType(Option::class);
    }

    public function it_should_detect_if_it_is_not_a_language_option(): void
    {
        $this->isLanguageTag()->shouldBeEqualTo(false);
    }
    
    public function it_should_detect_if_it_is_a_language_option(): void
    {
        $this->beConstructedWith('lang-en');
        
        $this->isLanguageTag()->shouldBeEqualTo(true);
    }

    public function it_should_detect_if_it_is_not_a_range_option(): void
    {
        $this->isRange()->shouldBeEqualTo(false);
    }

    public function it_should_detect_if_it_is_a_range_option(): void
    {
        $this->beConstructedWith('range=0-1500');

        $this->isRange()->shouldBeEqualTo(true);
    }
    
    public function it_should_get_the_high_range_value_of_an_option(): void
    {
        $this->beConstructedWith('range=0-1500');
        
        $this->getHighRange()->shouldBeEqualTo('1500');
    }
    
    public function it_should_return_an_empty_string_if_the_high_range_cannot_be_parsed(): void
    {
        $this->getHighRange()->shouldBeEqualTo('');
    }
    
    public function it_should_get_the_low_range_value_of_an_option(): void
    {
        $this->beConstructedWith('range=0-1500');

        $this->getLowRange()->shouldBeEqualTo('0');
    }

    public function it_should_return_null_if_the_low_range_cannot_be_parsed(): void
    {
        $this->getLowRange()->shouldBeNull();
    }
    
    public function it_should_have_a_factory_method_for_a_range(): void
    {
        $this->beConstructedThrough('fromRange', ['0']);
        
        $this->isRange()->shouldBeEqualTo(true);
        $this->getLowRange()->shouldBeEqualTo('0');
        $this->getHighRange()->shouldBeEqualTo('*');
    }
    
    public function it_should_return_whether_the_option_starts_with_a_string(): void
    {
        $this->startsWith('fo')->shouldBeEqualTo(true);
        $this->startsWith('bar')->shouldBeEqualTo(false);
    }
    
    public function it_should_get_the_string_option_with_toString(): void
    {
        $this->toString()->shouldBeEqualTo('foo');
    }
    
    public function it_should_have_a_string_representation(): void
    {
        $this->__toString()->shouldBeEqualTo('foo');
    }
    
    public function it_should_check_for_equality_with_another_option(): void
    {
        $this->equals(new Option('FOO'))->shouldBeEqualTo(true);
        $this->equals(new Option('foo'))->shouldBeEqualTo(true);
        $this->equals(new Option('bar'))->shouldBeEqualTo(false);
    }
}
