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

namespace FreeDSx\Ldap\Operation\Request\PasswordPolicy;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\EnumeratedType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Asn1\Type\SetType;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;

use function array_map;
use function array_values;
use function count;
use function is_int;

/**
 * FreeDSx-private extended op forwarding a replica's bind-originated password-policy state to the primary.
 *
 * ForwardPasswordPolicyStateValue ::= SEQUENCE {
 *     dn         OCTET STRING,
 *     entryUuid  OCTET STRING,
 *     state      SEQUENCE OF PolicyStateAttribute }
 *
 * PolicyStateAttribute ::= SEQUENCE {
 *     field   ENUMERATED { pwdFailureTime(0), pwdAccountLockedTime(1), pwdLastSuccess(2), pwdGraceUseTime(3) },
 *     values  SET OF OCTET STRING }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ForwardPasswordPolicyStateRequest extends ExtendedRequest
{
    private Dn $dn;

    /**
     * @var PasswordPolicyStateAttribute[]
     */
    private array $state;

    /**
     * @param PasswordPolicyStateAttribute[] $state
     */
    public function __construct(
        Dn|string $dn,
        private string $entryUuid = '',
        array $state = [],
    ) {
        $this->dn = $dn instanceof Dn
            ? $dn
            : new Dn($dn);
        $this->state = array_values($state);
        parent::__construct(ExtendedRequest::OID_PPOLICY_STATE_FORWARD);
    }

    public function getDn(): Dn
    {
        return $this->dn;
    }

    public function getEntryUuid(): string
    {
        return $this->entryUuid;
    }

    /**
     * @return PasswordPolicyStateAttribute[]
     */
    public function getState(): array
    {
        return $this->state;
    }

    public function toAsn1(): SequenceType
    {
        $state = Asn1::sequenceOf();

        foreach ($this->state as $attribute) {
            $state->addChild(Asn1::sequence(
                Asn1::enumerated($attribute->field->value),
                Asn1::setOf(...array_map(
                    static fn(string $value): OctetStringType => Asn1::octetString($value),
                    $attribute->values,
                )),
            ));
        }

        $this->requestValue = Asn1::sequence(
            Asn1::octetString($this->dn->toString()),
            Asn1::octetString($this->entryUuid),
            $state,
        );

        return parent::toAsn1();
    }

    /**
     * {@inheritDoc}
     *
     * @param AbstractType<mixed> $type
     * @throws EncoderException
     * @throws PartialPduException
     * @throws ProtocolException
     */
    public static function fromAsn1(AbstractType $type): static
    {
        $request = self::decodeEncodedValue($type);
        if (!($request instanceof SequenceType) || count($request->getChildren()) !== 3) {
            throw new ProtocolException('The password policy forward request is malformed.');
        }

        $dn = $request->getChild(0);
        $entryUuid = $request->getChild(1);
        $state = $request->getChild(2);
        if (!($dn instanceof OctetStringType && $entryUuid instanceof OctetStringType && $state instanceof SequenceType)) {
            throw new ProtocolException('The password policy forward request is malformed.');
        }

        $attributes = [];
        foreach ($state->getChildren() as $attribute) {
            $attributes[] = self::parseStateAttribute($attribute);
        }

        return new static(
            $dn->getValue(),
            $entryUuid->getValue(),
            $attributes,
        );
    }

    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     */
    private static function parseStateAttribute(AbstractType $type): PasswordPolicyStateAttribute
    {
        if (!($type instanceof SequenceType) || count($type->getChildren()) !== 2) {
            throw new ProtocolException('The password policy forward state attribute is malformed.');
        }

        $field = $type->getChild(0);
        $values = $type->getChild(1);
        if (!($field instanceof EnumeratedType && $values instanceof SetType)) {
            throw new ProtocolException('The password policy forward state attribute is malformed.');
        }

        $fieldNumber = $field->getValue();
        $stateField = is_int($fieldNumber)
            ? PasswordPolicyStateField::tryFrom($fieldNumber)
            : null;
        if ($stateField === null) {
            throw new ProtocolException('The password policy forward state field is unrecognized.');
        }

        $decoded = [];
        foreach ($values->getChildren() as $value) {
            if (!$value instanceof OctetStringType) {
                throw new ProtocolException('The password policy forward state attribute is malformed.');
            }
            $decoded[] = $value->getValue();
        }

        return new PasswordPolicyStateAttribute(
            $stateField,
            $decoded,
        );
    }
}
