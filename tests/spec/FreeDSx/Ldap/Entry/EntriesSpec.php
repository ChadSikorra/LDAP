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

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use PhpSpec\ObjectBehavior;

class EntriesSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(new Entry('foo'), new Entry('bar'));
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(Entries::class);
    }

    public function it_should_implement_countable(): void
    {
        $this->shouldImplement('\Countable');
    }

    public function it_should_implement_iterator_aggregate(): void
    {
        $this->shouldImplement('\IteratorAggregate');
    }

    public function it_should_get_the_count(): void
    {
        $this->count()->shouldBeEqualTo(2);
    }

    public function it_should_get_the_first_entry(): void
    {
        $this->first()->shouldBeLike(new Entry('foo'));
    }

    public function it_should_return_null_if_the_first_entry_does_not_exist(): void
    {
        $this->beConstructedWith(...[]);

        $this->first()->shouldBeNull();
    }

    public function it_should_get_the_last_entry(): void
    {
        $this->last()->shouldBeLike(new Entry('bar'));
    }

    public function it_should_return_null_if_the_last_entry_does_not_exist(): void
    {
        $this->beConstructedWith(...[]);

        $this->last()->shouldBeNull();
    }

    public function it_should_add_entries(): void
    {
        $this->add(new Entry('cn=new'), new Entry('cn=another'));
        $this->count()->shouldBeEqualTo(4);
    }

    public function it_should_remove_entries(): void
    {
        $entry1 = new Entry('cn=new');
        $entry2 = new Entry('cn=another');
        $this->add($entry1, $entry2);
        $this->remove($entry1, $entry2);
        $this->count()->shouldBeEqualTo(2);
    }

    public function it_should_not_remove_entries_if_they_dont_exist(): void
    {
        $this->remove(new Entry('cn=meh'));
        $this->count()->shouldBeEqualTo(2);
    }

    public function it_should_check_if_an_entry_object_is_in_the_collection(): void
    {
        $entry = new Entry('cn=meh');
        $this->has($entry)->shouldBeEqualTo(false);
        $this->add($entry);
        $this->has($entry)->shouldBeEqualTo(true);
    }

    public function it_should_check_if_an_entry_is_in_the_collection_by_dn(): void
    {
        $this->has('foo')->shouldBeEqualTo(true);
        $this->has('cn=meh')->shouldBeEqualTo(false);
    }

    public function it_should_get_an_entry_by_dn(): void
    {
        $this->get('foo')->shouldBeLike(new Entry('foo'));
    }

    public function it_should_return_null_when_trying_to_get_an_entry_that_doesnt_exist(): void
    {
        $this->get('meh')->shouldBeNull();
    }

    public function it_should_get_the_array_of_entries(): void
    {
        $this->toArray()->shouldBeLike([
            new Entry('foo'),
            new Entry('bar')
        ]);
    }
}
