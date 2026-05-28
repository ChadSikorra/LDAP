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
 * The set of LDIF modify mod-spec operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum ModSpecOp: string
{
    case Add = 'add';

    case Delete = 'delete';

    case Replace = 'replace';
}
