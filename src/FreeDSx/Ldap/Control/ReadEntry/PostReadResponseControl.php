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

namespace FreeDSx\Ldap\Control\ReadEntry;

/**
 * Post-Read response control. RFC 4527. Returns the entry state from after the modification.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PostReadResponseControl extends ReadEntryResponseControl
{
    protected static function oid(): string
    {
        return self::OID_POST_READ;
    }
}
