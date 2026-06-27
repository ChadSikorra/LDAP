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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal\Read;

/**
 * The DIT extent a change stream covers.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum ScopeType
{
    case BaseObject;
    case OneLevel;
    case WholeSubtree;
}
