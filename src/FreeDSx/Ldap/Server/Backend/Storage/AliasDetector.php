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

namespace FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\ObjectClassOid;

use function strcasecmp;

/**
 * Recognizes alias entries (RFC 4512: an entry whose objectClass includes "alias").
 */
final class AliasDetector
{
    private function __construct() {}

    public static function isAlias(Entry $entry): bool
    {
        $objectClass = $entry->get('objectClass');
        if ($objectClass === null) {
            return false;
        }

        foreach ($objectClass->getValues() as $value) {
            if (strcasecmp($value, ObjectClassOid::NAME_ALIAS) === 0) {
                return true;
            }
        }

        return false;
    }
}
