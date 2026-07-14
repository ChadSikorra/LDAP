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

use function array_values;

/**
 * One forwarded password-policy field and its resulting state: the full replacement values, or none to clear it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PasswordPolicyStateAttribute
{
    /**
     * @var string[]
     */
    public array $values;

    /**
     * @param string[] $values The full replacement value set; an empty set clears (resets) the attribute.
     */
    public function __construct(
        public PasswordPolicyStateField $field,
        array $values = [],
    ) {
        $this->values = array_values($values);
    }

    public static function clear(PasswordPolicyStateField $field): self
    {
        return new self($field);
    }
}
