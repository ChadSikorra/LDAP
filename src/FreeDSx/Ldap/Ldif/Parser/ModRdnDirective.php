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
 * The set of directives permitted in a modrdn change record body.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum ModRdnDirective: string
{
    case NewRdn = 'newrdn';

    case DeleteOldRdn = 'deleteoldrdn';

    case NewSuperior = 'newsuperior';
}
