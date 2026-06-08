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

namespace FreeDSx\Ldap\Protocol\Authorization;

/**
 * The form of an authorization identity.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum AuthzIdType: string
{
    case Anonymous = '';

    case Dn = 'dn:';

    case Username = 'u:';
}
