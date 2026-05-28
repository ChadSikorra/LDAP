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

namespace FreeDSx\Ldap\Ldif\Parser;

/**
 * The set of RFC 2849 changetype values (moddn is an alias of modrdn).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum ChangeType: string
{
    case Add = 'add';

    case Delete = 'delete';

    case Modify = 'modify';

    case ModRdn = 'modrdn';

    case ModDn = 'moddn';
}
