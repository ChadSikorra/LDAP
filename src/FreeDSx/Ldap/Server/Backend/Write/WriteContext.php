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

namespace FreeDSx\Ldap\Server\Backend\Write;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Carries request-scoped metadata (identity, controls) for write operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class WriteContext
{
    public function __construct(
        private TokenInterface $token,
        private ControlBag $controls,
        private bool $isSystem = false,
        private RelaxedSchemaViolations $relaxedViolations = new RelaxedSchemaViolations(),
    ) {}

    /**
     * Build a context for a server-initiated write that bypasses {@see SchemaValidator}.
     */
    public static function system(
        TokenInterface $token,
        ControlBag $controls,
    ): self {
        return new self(
            $token,
            $controls,
            isSystem: true,
        );
    }

    /**
     * Bound DN of the authenticated user, or null for anonymous.
     */
    public function getBoundDn(): ?string
    {
        return $this->token->getUsername();
    }

    public function isAnonymous(): bool
    {
        return $this->token->getUsername() === null;
    }

    public function isSystem(): bool
    {
        return $this->isSystem;
    }

    public function getLdapVersion(): int
    {
        return $this->token->getVersion();
    }

    public function getControls(): ControlBag
    {
        return $this->controls;
    }

    public function relaxedViolations(): RelaxedSchemaViolations
    {
        return $this->relaxedViolations;
    }
}
