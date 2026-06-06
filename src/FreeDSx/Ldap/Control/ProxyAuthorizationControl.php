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

namespace FreeDSx\Ldap\Control;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;

/**
 * Represents a proxied authorization control. RFC 4370.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ProxyAuthorizationControl extends Control
{
    public function __construct(
        private string $authzId = '',
        bool $criticality = true,
    ) {
        parent::__construct(
            self::OID_PROXY_AUTHORIZATION,
            $criticality,
        );
    }

    /**
     * The authorization identity to assume: an authzId ("dn:..." / "u:..."), or empty for anonymous.
     */
    public function getAuthzId(): string
    {
        return $this->authzId;
    }

    public function setAuthzId(string $authzId): self
    {
        $this->authzId = $authzId;

        return $this;
    }

    public function toAsn1(): SequenceType
    {
        $this->controlValue = $this->authzId;

        return parent::toAsn1();
    }

    /**
     * {@inheritDoc}
     *
     * @param AbstractType<mixed> $type
     */
    public static function fromAsn1(AbstractType $type): static
    {
        if (!$type instanceof SequenceType) {
            throw new ProtocolException(sprintf(
                'Expected a sequence type for a proxy authorization control, but received: %s',
                get_class($type),
            ));
        }

        [1 => $criticality, 2 => $authzId] = self::parseAsn1ControlValues($type);

        return new static(
            $authzId ?? '',
            $criticality,
        );
    }
}
