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

use FreeDSx\Ldap\Exception\InvalidArgumentException;

use function bin2hex;
use function chr;
use function hex2bin;
use function ord;
use function random_bytes;
use function str_replace;
use function str_split;
use function strlen;
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

    /**
     * The 16-byte binary form of a dashed UUID string, as RFC 4533 sync controls carry it.
     *
     * @throws InvalidArgumentException when the value is not a UUID
     */
    public static function toBinary(string $uuid): string
    {
        $binary = hex2bin(str_replace('-', '', $uuid));

        if ($binary === false || strlen($binary) !== 16) {
            throw new InvalidArgumentException(sprintf('"%s" is not a valid UUID.', $uuid));
        }

        return $binary;
    }
}
