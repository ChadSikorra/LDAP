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

namespace FreeDSx\Ldap\Server\AccessControl;

use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ControlRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\Effect;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;

/**
 * The rule sets and defaults that configure {@see RuleBasedAccessControl}.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class AclRules
{
    /**
     * @param OperationRule[] $operations Evaluated in order; first match wins.
     * @param AttributeRule[] $attributes Evaluated per attribute in order; first match wins.
     * @param ControlRule[] $controls Evaluated per control in order; first match wins.
     * @param Effect $defaultOperationEffect Applied when no operation rule matches.
     * @param Effect $defaultControlEffect Applied when no control rule matches (controls are gated, so Deny).
     */
    public function __construct(
        public array $operations = [],
        public array $attributes = [],
        public array $controls = [],
        public Effect $defaultOperationEffect = Effect::Deny,
        public Effect $defaultControlEffect = Effect::Deny,
    ) {}

    public function withOperationRules(OperationRule ...$operations): self
    {
        return new self(
            $operations,
            $this->attributes,
            $this->controls,
            $this->defaultOperationEffect,
            $this->defaultControlEffect,
        );
    }

    public function withAttributeRules(AttributeRule ...$attributes): self
    {
        return new self(
            $this->operations,
            $attributes,
            $this->controls,
            $this->defaultOperationEffect,
            $this->defaultControlEffect,
        );
    }

    public function withControlRules(ControlRule ...$controls): self
    {
        return new self(
            $this->operations,
            $this->attributes,
            $controls,
            $this->defaultOperationEffect,
            $this->defaultControlEffect,
        );
    }

    public function withDefaultOperationEffect(Effect $effect): self
    {
        return new self(
            $this->operations,
            $this->attributes,
            $this->controls,
            $effect,
            $this->defaultControlEffect,
        );
    }

    public function withDefaultControlEffect(Effect $effect): self
    {
        return new self(
            $this->operations,
            $this->attributes,
            $this->controls,
            $this->defaultOperationEffect,
            $effect,
        );
    }

    public function isEmpty(): bool
    {
        return $this->operations === []
            && $this->attributes === []
            && $this->controls === [];
    }
}
