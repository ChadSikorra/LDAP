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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal\Change;

/**
 * The kind of write a change-journal record captures.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum ChangeType: string
{
    case Add = 'add';
    case Modify = 'modify';
    case Delete = 'delete';
    case ModRdn = 'modrdn';
}
