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

namespace FreeDSx\Ldap\Server\Utility;

use function bin2hex;
use function chr;
use function ord;
use function random_bytes;
use function str_split;
use function vsprintf;

/**
 * Generates RFC 4122 compliant UUIDs.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class Uuid
{
    private function __construct() {}

    /**
     * Generates a random UUID v4 string.
     */
    public static function v4(): string
    {
        $bytes = random_bytes(16);

        // Set version 4 and RFC 4122 variant bits.
        $bytes[6] = chr(ord($bytes[6]) & 0x0f | 0x40);
        $bytes[8] = chr(ord($bytes[8]) & 0x3f | 0x80);

        return vsprintf(
            '%s%s-%s-%s-%s-%s%s%s',
            str_split(
                bin2hex($bytes),
                4,
            ),
        );
    }
}
