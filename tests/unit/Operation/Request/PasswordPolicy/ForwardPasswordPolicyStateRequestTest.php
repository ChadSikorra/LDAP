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

namespace Tests\Unit\FreeDSx\Ldap\Operation\Request\PasswordPolicy;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\PasswordPolicy\ForwardPasswordPolicyStateRequest;
use FreeDSx\Ldap\Operation\Request\PasswordPolicy\PasswordPolicyStateAttribute;
use FreeDSx\Ldap\Operation\Request\PasswordPolicy\PasswordPolicyStateField;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

final class ForwardPasswordPolicyStateRequestTest extends TestCase
{
    private ForwardPasswordPolicyStateRequest $subject;

    protected function setUp(): void
    {
        $this->subject = new ForwardPasswordPolicyStateRequest(
            'cn=user,dc=foo,dc=bar',
            'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
            [
                new PasswordPolicyStateAttribute(
                    PasswordPolicyStateField::FailureTime,
                    ['20260101000000Z', '20260101000100Z'],
                ),
                PasswordPolicyStateAttribute::clear(PasswordPolicyStateField::AccountLockedTime),
            ],
        );
    }

    public function test_it_exposes_the_dn_uuid_and_state(): void
    {
        self::assertSame(
            'cn=user,dc=foo,dc=bar',
            $this->subject->getDn()->toString(),
        );
        self::assertSame(
            'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
            $this->subject->getEntryUuid(),
        );
        self::assertCount(
            2,
            $this->subject->getState(),
        );
    }

    public function test_it_uses_the_forward_oid(): void
    {
        self::assertSame(
            ExtendedRequest::OID_PPOLICY_STATE_FORWARD,
            $this->subject->getName(),
        );
    }

    public function test_it_generates_the_expected_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            Asn1::application(23, Asn1::sequence(
                Asn1::context(0, Asn1::octetString(ExtendedRequest::OID_PPOLICY_STATE_FORWARD)),
                Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::octetString('cn=user,dc=foo,dc=bar'),
                    Asn1::octetString('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
                    Asn1::sequenceOf(
                        Asn1::sequence(
                            Asn1::enumerated(0),
                            Asn1::setOf(
                                Asn1::octetString('20260101000000Z'),
                                Asn1::octetString('20260101000100Z'),
                            ),
                        ),
                        Asn1::sequence(
                            Asn1::enumerated(1),
                            Asn1::setOf(),
                        ),
                    ),
                )))),
            )),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_round_trips_through_asn1(): void
    {
        $result = ForwardPasswordPolicyStateRequest::fromAsn1($this->subject->toAsn1());

        self::assertEquals(
            $this->subject->setValue(null),
            $result->setValue(null),
        );
    }

    public function test_it_rejects_an_unknown_state_field(): void
    {
        $this->expectException(ProtocolException::class);

        ForwardPasswordPolicyStateRequest::fromAsn1(
            (new ExtendedRequest(ExtendedRequest::OID_PPOLICY_STATE_FORWARD))
                ->setValue(Asn1::sequence(
                    Asn1::octetString('cn=user,dc=foo,dc=bar'),
                    Asn1::octetString('uuid'),
                    Asn1::sequenceOf(Asn1::sequence(
                        Asn1::enumerated(99),
                        Asn1::setOf(Asn1::octetString('x')),
                    )),
                ))
                ->toAsn1(),
        );
    }

    public function test_it_rejects_malformed_asn1(): void
    {
        $this->expectException(ProtocolException::class);

        ForwardPasswordPolicyStateRequest::fromAsn1(
            (new ExtendedRequest(ExtendedRequest::OID_PPOLICY_STATE_FORWARD))
                ->setValue(Asn1::set())
                ->toAsn1(),
        );
    }
}
