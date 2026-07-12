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

namespace FreeDSx\Ldap\Server\AccessControl\Rule;

/**
 * The access direction an attribute rule applies to.
 *
 * A request is always Read or Write, a rule may be Both.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum AttributeAccess
{
    case Read;

    case Write;

    case Both;

    /**
     * Whether a rule with this scope applies to the requested access direction.
     */
    public function includes(self $requested): bool
    {
        return $this === self::Both
            || $this === $requested;
    }
}
