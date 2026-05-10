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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\Effect;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Evaluates an ordered list of rules; first match wins.
 *
 * When no operation rule matches, $defaultEffect is applied (default: Deny).
 * When no attribute rule matches an attribute, the attribute is kept (default allow).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class RuleBasedAccessControl implements AccessControlInterface, BackendAwareInterface
{
    /**
     * @param OperationRule[] $operationRules Evaluated in order; first match wins.
     * @param AttributeRule[] $attributeRules Evaluated per attribute in order; first match wins.
     * @param Effect          $defaultEffect  Applied when no operation rule matches.
     */
    public function __construct(
        private readonly array $operationRules = [],
        private readonly array $attributeRules = [],
        private readonly Effect $defaultEffect = Effect::Deny,
    ) {}

    public function setBackend(LdapBackendInterface $backend): void
    {
        foreach ($this->operationRules as $rule) {
            if ($rule->subject instanceof BackendAwareInterface) {
                $rule->subject->setBackend($backend);
            }
        }

        foreach ($this->attributeRules as $rule) {
            if ($rule->subject instanceof BackendAwareInterface) {
                $rule->subject->setBackend($backend);
            }
        }
    }

    /**
     * @throws OperationException
     */
    public function authorizeOperation(
        OperationType $operation,
        TokenInterface $token,
        Dn $dn,
    ): void {
        if (!$this->isAllowed($operation, $token, $dn)) {
            $this->deny();
        }
    }

    /**
     * @throws OperationException
     */
    public function authorizeAttribute(
        TokenInterface $token,
        Dn $dn,
        string $attribute,
    ): void {
        $effect = $this->resolveAttributeEffect(
            $token,
            $dn,
            strtolower($attribute),
        );

        if ($effect === Effect::Deny) {
            $this->deny();
        }
    }

    public function filterEntry(
        TokenInterface $token,
        Entry $entry,
    ): ?Entry {
        $dn = $entry->getDn();

        if (!$this->isAllowed(OperationType::Search, $token, $dn)) {
            return null;
        }

        if ($this->attributeRules === []) {
            return $entry;
        }

        $allAttributes = $entry->getAttributes();
        $kept = [];

        foreach ($allAttributes as $attribute) {
            $effect = $this->resolveAttributeEffect(
                $token,
                $dn,
                strtolower($attribute->getName()),
            );

            if ($effect !== Effect::Deny) {
                $kept[] = $attribute;
            }
        }

        if (count($kept) === count($allAttributes)) {
            return $entry;
        }

        return Entry::raw(
            $dn,
            $kept,
        );
    }

    private function isAllowed(
        OperationType $operation,
        TokenInterface $token,
        Dn $dn,
    ): bool {
        foreach ($this->operationRules as $rule) {
            if (!$this->operationMatches($rule, $operation)) {
                continue;
            }

            if (!$rule->target->matches($dn)) {
                continue;
            }

            if (!$rule->subject->matches($token, $dn)) {
                continue;
            }

            return $rule->effect === Effect::Allow;
        }

        return $this->defaultEffect === Effect::Allow;
    }

    private function operationMatches(
        OperationRule $rule,
        OperationType $operation,
    ): bool {
        return $rule->operations === []
            || in_array($operation, $rule->operations, true);
    }

    private function resolveAttributeEffect(
        TokenInterface $token,
        Dn $dn,
        string $attrName,
    ): ?Effect {
        foreach ($this->attributeRules as $rule) {
            if (!$rule->target->matches($dn)) {
                continue;
            }

            if (!$rule->subject->matches($token, $dn)) {
                continue;
            }

            if ($rule->attributes !== [] && !in_array($attrName, $rule->attributes, true)) {
                continue;
            }

            return $rule->effect;
        }

        return null;
    }

    /**
     * @throws OperationException
     */
    private function deny(): never
    {
        throw new OperationException(
            'Access denied.',
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
        );
    }
}
