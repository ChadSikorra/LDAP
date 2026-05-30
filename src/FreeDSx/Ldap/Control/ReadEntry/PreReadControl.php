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
 * Pre-Read request control. RFC 4527. Requests the entry state from before the modification.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PreReadControl extends ReadEntryControl
{
    protected static function oid(): string
    {
        return self::OID_PRE_READ;
    }
}
