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

namespace spec\FreeDSx\Ldap\Operation\Response;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use PhpSpec\ObjectBehavior;

class SearchResultEntrySpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(Entry::create('cn=foo,dc=foo,dc=bar', ['cn' => 'foo']));
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(SearchResultEntry::class);
    }

    public function it_should_get_the_entry(): void
    {
        $this->getEntry()->shouldBeLike(Entry::create('cn=foo,dc=foo,dc=bar', ['cn' => 'foo']));
    }

    public function it_should_be_constructed_from_asn1(): void
    {
        $this->beConstructedThrough('fromAsn1', [Asn1::application(4, Asn1::sequence(
            Asn1::octetString('dc=foo,dc=bar'),
            Asn1::sequenceOf(
                Asn1::sequence(
                    Asn1::octetString('cn'),
                    Asn1::sequenceOf(
                        Asn1::octetString('foo')
                    )
                ),
                Asn1::sequence(
                    Asn1::octetString('sn'),
                    Asn1::sequenceOf(
                        Asn1::octetString('foo'),
                        Asn1::octetString('bar')
                    )
                )
            )
        ))]);

        $this->getEntry()->shouldBeLike(Entry::create('dc=foo,dc=bar', ['cn' => ['foo'], 'sn' => ['foo', 'bar']]));
    }

    public function it_should_generate_correct_asn1(): void
    {
        $this->toAsn1()->shouldBeLike(Asn1::application(4, Asn1::sequence(
            Asn1::octetString('cn=foo,dc=foo,dc=bar'),
            Asn1::sequenceOf(
                Asn1::sequence(
                    Asn1::octetString('cn'),
                    Asn1::setOf(
                        Asn1::octetString('foo')
                    )
                )
            )
        )));
    }
}
