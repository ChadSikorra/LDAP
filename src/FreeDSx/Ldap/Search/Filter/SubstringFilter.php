<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Search\Filter;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use Stringable;

/**
 * Represents a substring filter. RFC 4511, 4.5.1.7.2.
 *
 * SubstringFilter ::= SEQUENCE {
 *     type           AttributeDescription,
 *     substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
 *         initial [0] AssertionValue,  -- can occur at most once
 *         any     [1] AssertionValue,
 *         final   [2] AssertionValue } -- can occur at most once
 *     }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SubstringFilter implements FilterInterface, Stringable
{
    use FilterAttributeTrait;

    protected const CHOICE_TAG = 4;

    private ?string $startsWith;

    private ?string $endsWith;

    /**
     * @var string[]
     */
    private array $contains;

    public function __construct(
        string $attribute,
        ?string $startsWith = null,
        ?string $endsWith = null,
        string ...$contains
    ) {
        $this->attribute = $attribute;
        $this->startsWith = $startsWith;
        $this->endsWith = $endsWith;
        $this->contains = $contains;
    }

    /**
     * Get the value that it should start with.
     */
    public function getStartsWith(): ?string
    {
        return $this->startsWith;
    }

    /**
     * Set the value it should start with.
     */
    public function setStartsWith(?string $value): self
    {
        $this->startsWith = $value;

        return $this;
    }

    /**
     * Get the value it should end with.
     */
    public function getEndsWith(): ?string
    {
        return $this->endsWith;
    }

    /**
     * Set the value it should end with.
     */
    public function setEndsWith(?string $value): self
    {
        $this->endsWith = $value;

        return $this;
    }

    /**
     * Get the values it should contain.
     *
     * @return string[]
     */
    public function getContains(): array
    {
        return $this->contains;
    }

    /**
     * Set the values it should contain.
     */
    public function setContains(string ...$values): self
    {
        $this->contains = $values;

        return $this;
    }

    /**
     * @throws RuntimeException
     */
    public function toAsn1(): AbstractType
    {
        if ($this->startsWith === null && $this->endsWith === null && count($this->contains) === 0) {
            throw new RuntimeException('You must provide a contains, starts with, or ends with value to the substring filter.');
        }
        $substrings = Asn1::sequenceOf();

        if ($this->startsWith !== null) {
            $substrings->addChild(Asn1::context(
                tagNumber: 0,
                type: Asn1::octetString($this->startsWith)
            ));
        }

        foreach ($this->contains as $contain) {
            $substrings->addChild(Asn1::context(
                tagNumber: 1,
                type: Asn1::octetString($contain),
            ));
        }

        if ($this->endsWith !== null) {
            $substrings->addChild(Asn1::context(
                tagNumber: 2,
                type: Asn1::octetString($this->endsWith),
            ));
        }

        return Asn1::context(
            tagNumber: self::CHOICE_TAG,
            type: Asn1::sequence(
                Asn1::octetString($this->attribute),
                $substrings
            )
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toString(): string
    {
        $filter = self::PAREN_LEFT . $this->attribute . self::FILTER_EQUAL;

        $value = '';
        if (count($this->contains) !== 0) {
            $value = array_map(function ($value) {
                return Attribute::escape($value);
            }, $this->contains);
            $value = '*' . implode('*', $value) . '*';
        }
        if ($this->startsWith !== null) {
            $startsWith = Attribute::escape($this->startsWith);
            $value = ($value === '' ? $startsWith . '*' : $startsWith) . $value;
        }
        if ($this->endsWith !== null) {
            $endsWith = Attribute::escape($this->endsWith);
            $value = $value . ($value === '' ? '*' . $endsWith : $endsWith);
        }

        return $filter . $value . self::PAREN_RIGHT;
    }

    /**
     * {@inheritDoc}
     * @throws EncoderException
     */
    public static function fromAsn1(AbstractType $type): self
    {
        $encoder = new LdapEncoder();
        $type = $type instanceof IncompleteType ? $encoder->complete($type, AbstractType::TAG_TYPE_SEQUENCE) : $type;
        if (!($type instanceof SequenceType && count($type->getChildren()) === 2)) {
            throw new ProtocolException('The substring type is malformed');
        }

        $attrType = $type->getChild(0);
        $substrings = $type->getChild(1);
        if (!($attrType instanceof OctetStringType && $substrings instanceof SequenceType && count($substrings) > 0)) {
            throw new ProtocolException('The substring filter is malformed.');
        }
        [$startsWith, $endsWith, $contains] = self::parseSubstrings($substrings);

        return new self(
            $attrType->getValue(),
            $startsWith,
            $endsWith,
            ...$contains
        );
    }

    /**
     * @return array{0: string|null, 1: string|null, 2: string[]}
     * @throws ProtocolException
     */
    protected static function parseSubstrings(SequenceType $substrings): array
    {
        /** @var OctetStringType|null $startsWith */
        $startsWith = null;
        /** @var OctetStringType|null $endsWith */
        $endsWith = null;
        /** @var  string[] $contains */
        $contains = [];

        foreach ($substrings->getChildren() as $substring) {
            if ($substring->getTagClass() !== AbstractType::TAG_CLASS_CONTEXT_SPECIFIC) {
                throw new ProtocolException('The substring filter is malformed.');
            }
            # Starts With and Ends With can occur only once each. Contains can occur multiple times.
            if ($substring->getTagNumber() === 0) {
                if ($startsWith !== null) {
                    throw new ProtocolException('The substring filter is malformed.');
                } else {
                    $startsWith = $substring;
                }
            } elseif ($substring->getTagNumber() === 1) {
                $value = $substring->getValue();
                if (!is_string($value)) {
                    $value = '';
                }
                $contains[] = $value;
            } elseif ($substring->getTagNumber() === 2) {
                if ($endsWith !== null) {
                    throw new ProtocolException('The substring filter is malformed.');
                } else {
                    $endsWith = $substring;
                }
            } else {
                throw new ProtocolException('The substring filter is malformed.');
            }
        }

        $startsWith = $startsWith?->getValue();
        $endsWith = $endsWith?->getValue();

        return [
            is_string($startsWith) ? $startsWith : null,
            is_string($endsWith) ? $endsWith : null,
            $contains
        ];
    }
}
