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

namespace FreeDSx\Ldap\Control\Ad;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ProtocolException;

/**
 * Implements the AD PolicyHints control.
 *
 *  PolicyHintsRequestValue ::= SEQUENCE {
 *      Flags    INTEGER
 *  }
 *
 * @see https://msdn.microsoft.com/en-us/library/hh128228.aspx
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PolicyHintsControl extends Control
{
    public function __construct(private bool $isEnabled = true)
    {
        parent::__construct(
            self::OID_POLICY_HINTS,
            true
        );
    }

    public function setIsEnabled(bool $isEnabled): self
    {
        $this->isEnabled = $isEnabled;

        return $this;
    }

    public function getIsEnabled(): bool
    {
        return $this->isEnabled;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $this->controlValue = Asn1::sequence(Asn1::integer($this->isEnabled ? 1 : 0));

        return parent::toAsn1();
    }

    /**
     * {@inheritDoc}
     * @throws EncoderException
     * @throws PartialPduException
     */
    public static function fromAsn1(AbstractType $type): static
    {
        $request = self::decodeEncodedValue($type);
        if (!$request instanceof SequenceType) {
            throw new ProtocolException('A PolicyHints control value must be a sequence type.');
        }
        $isEnabled = $request->getChild(0);
        if (!$isEnabled instanceof IntegerType) {
            throw new ProtocolException('A PolicyHints control value sequence 0 must be an integer type.');
        }
        $control = new static((bool) $isEnabled->getValue());

        return self::mergeControlData(
            $control,
            $type
        );
    }
}
