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

namespace spec\FreeDSx\Ldap;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\UrlParseException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\LdapUrlExtension;
use PhpSpec\ObjectBehavior;

class LdapUrlSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith('foo');
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(LdapUrl::class);
    }

    public function it_should_have_a_string_representation(): void
    {
        $this->toString()->shouldBeEqualTo('ldap://foo/');
    }

    public function it_should_parse_a_url_with_no_host_but_a_path(): void
    {
        $this::parse('ldap:///o=University%20of%20Michigan,c=US')->shouldBeLike(
            (new LdapUrl())->setDn('o=University of Michigan,c=US')
        );
    }

    public function it_should_generate_a_url_with_no_host_but_a_path(): void
    {
        $this->beConstructedWith(null);
        $this->setDn('o=University of Michigan,c=US');

        $this->toString()->shouldBeEqualTo('ldap:///o=University%20of%20Michigan,c=US');
    }

    public function it_should_parse_a_url_with_a_host_and_path_but_no_query_elements(): void
    {
        $this::parse('ldap://ldap1.example.net/o=University%20of%20Michigan,c=US')->shouldBeLike(
            (new LdapUrl('ldap1.example.net'))->setDn('o=University of Michigan,c=US')
        );
    }

    public function it_should_generate_a_url_with_a_host_and_path_but_no_query_elements(): void
    {
        $this->beConstructedWith('ldap1.example.net');
        $this->setDn('o=University of Michigan,c=US');

        $this->toString()->shouldBeEqualTo('ldap://ldap1.example.net/o=University%20of%20Michigan,c=US');
    }

    public function it_should_parse_a_url_with_a_host_path_and_attribute(): void
    {
        $this::parse('ldap://ldap1.example.net/o=University%20of%20Michigan,c=US?postalAddress')->shouldBeLike(
            (new LdapUrl('ldap1.example.net'))
                ->setDn('o=University of Michigan,c=US')
                ->setAttributes('postalAddress')
        );
    }

    public function it_should_generate_a_url_with_a_host_path_and_attribute(): void
    {
        $this->beConstructedWith('ldap1.example.net');
        $this->setDn('o=University of Michigan,c=US');
        $this->setAttributes('postalAddress');

        $this->toString()->shouldBeEqualTo('ldap://ldap1.example.net/o=University%20of%20Michigan,c=US?postalAddress');
    }

    public function it_should_parse_a_url_with_a_host_port_path_scope_and_filter(): void
    {
        $this::parse('ldap://ldap1.example.net:6666/o=University%20of%20Michigan,c=US??sub?(cn=Babs%20Jensen)')->shouldBeLike(
            (new LdapUrl('ldap1.example.net'))
                ->setPort(6666)
                ->setDn('o=University of Michigan,c=US')
                ->setFilter('(cn=Babs Jensen)')
                ->setScope('sub')
        );
    }

    public function it_should_generate_a_url_with_a_host_port_path_scope_and_filter(): void
    {
        $this->beConstructedWith('ldap1.example.net');
        $this->setDn('o=University of Michigan,c=US');
        $this->setPort(6666);
        $this->setScope('sub');
        $this->setFilter('(cn=Babs Jensen)');

        $this->toString()->shouldBeEqualTo('ldap://ldap1.example.net:6666/o=University%20of%20Michigan,c=US??sub?(cn=Babs%20Jensen)');
    }

    public function it_should_parse_a_url_with_a_host_path_single_scope_and_attribute(): void
    {
        $this::parse('LDAP://ldap1.example.com/c=GB?objectClass?ONE')->shouldBeLike(
            (new LdapUrl('ldap1.example.com'))
                ->setDn('c=GB')
                ->setAttributes('objectClass')
                ->setScope('one')
        );
    }

    public function it_should_generate_a_url_with_a_host_path_single_scope_and_attribute(): void
    {
        $this->beConstructedWith('ldap1.example.com');
        $this->setDn('c=GB');
        $this->setAttributes('objectClass');
        $this->setScope('ONE');

        $this->toString()->shouldBeEqualTo('ldap://ldap1.example.com/c=GB?objectClass?one');
    }

    public function it_should_parse_a_url_with_a_percent_encoded_question_mark_in_the_path(): void
    {
        $this::parse('ldap://ldap2.example.com/o=Question%3f,c=US?mail')->shouldBeLike(
            (new LdapUrl('ldap2.example.com'))
                ->setDn('o=Question?,c=US')
                ->setAttributes('mail')
        );
    }

    public function it_should_generate_a_url_with_a_percent_encoded_question_mark_in_the_path(): void
    {
        $this->beConstructedWith('ldap2.example.com');
        $this->setDn('o=Question?,c=US');
        $this->setAttributes('mail');

        $this->toString()->shouldBeEqualTo('ldap://ldap2.example.com/o=Question%3f,c=US?mail');
    }

    public function it_should_parse_a_url_with_percent_encoded_filter_that_was_hex_escaped(): void
    {
        $this::parse('ldap://ldap3.example.com/o=Babsco,c=US???(four-octet=%5c00%5c00%5c00%5c04)')->shouldBeLike(
            (new LdapUrl('ldap3.example.com'))
                ->setDn('o=Babsco,c=US')
                ->setFilter('(four-octet=\00\00\00\04)')
        );
    }

    public function it_should_generate_a_url_with_percent_encoded_filter_that_was_hex_escaped(): void
    {
        $this->beConstructedWith('ldap3.example.com');
        $this->setDn('o=Babsco,c=US');
        $this->setFilter('(four-octet=\00\00\00\04)');

        $this->toString()->shouldBeEqualTo('ldap://ldap3.example.com/o=Babsco,c=US???(four-octet=%5c00%5c00%5c00%5c04)');
    }

    public function it_should_parse_a_url_with_extensions(): void
    {
        $this::parse('ldap:///??sub??e-bindname=cn=Manager%2cdc=example%2cdc=com')->shouldBeLike(
            (new LdapUrl(null))
                ->setScope('sub')
                ->setExtensions(new LdapUrlExtension('e-bindname', 'cn=Manager,dc=example,dc=com'))
        );
    }

    public function it_should_generate_a_url_with_extensions(): void
    {
        $this->beConstructedWith(null);
        $this->setScope('sub');
        $this->setExtensions(new LdapUrlExtension('e-bindname', 'cn=Manager,dc=example,dc=com'));

        $this->toString()->shouldBeEqualTo('ldap:///??sub??e-bindname=cn=Manager%2cdc=example%2cdc=com');
    }

    public function it_should_parse_a_url_with_all_default_query_fields(): void
    {
        $this->parse('ldap://foo/????')->shouldBeLike(new LdapUrl('foo'));
        $this->parse('ldap:///????')->shouldBeLike(new LdapUrl());
    }

    public function it_should_set_the_port(): void
    {
        $this->getPort()->shouldBeNull();
        $this->setPort(9001)->getPort()->shouldBeEqualTo(9001);
    }

    public function it_should_set_the_scope(): void
    {
        $this->getScope()->shouldBeNull();
        $this->setScope('base')->getScope()->shouldBeEqualTo('base');
        $this->setScope('one')->getScope()->shouldBeEqualTo('one');
        $this->setScope('sub')->getScope()->shouldBeEqualTo('sub');
    }

    public function it_should_reject_an_invalid_scope(): void
    {
        $this->shouldThrow(InvalidArgumentException::class)->during('setScope', ['foo']);
    }

    public function it_should_set_the_filter(): void
    {
        $this->getFilter()->shouldBeNull();
        $this->setFilter('foo=null')->getFilter()->shouldBeEqualTo('foo=null');
    }

    public function it_should_set_the_dn(): void
    {
        $this->getDn()->shouldBeNull();
        $this->setDn('dc=foo')->getDn()->shouldBeLike(new Dn('dc=foo'));
    }

    public function it_should_set_the_attributes(): void
    {
        $this->getAttributes()->shouldBeEqualTo([]);
        $this->setAttributes('foo', 'bar')->getAttributes()->shouldBeLike([new Attribute('foo'), new Attribute('bar')]);
    }

    public function it_should_set_the_host(): void
    {
        $this->getHost()->shouldBeEqualTo('foo');
        $this->setHost('bar')->getHost()->shouldBeEqualTo('bar');
    }

    public function it_should_set_whether_or_not_ssl_is_used(): void
    {
        $this->getUseSsl()->shouldBeEqualTo(false);
        $this->setUseSsl(true)->getUseSsl()->shouldBeEqualTo(true);
    }

    public function it_should_throw_an_error_if_the_scheme_is_not_ldap(): void
    {
        $this->shouldThrow(UrlParseException::class)->during('parse', ['https://foo/?']);
        $this->shouldThrow(UrlParseException::class)->during('parse', ['https:///?']);
    }

    public function it_should_throw_an_error_on_a_malformed_url(): void
    {
        $this->shouldThrow(UrlParseException::class)->during('parse', ['ldap']);
    }
}
