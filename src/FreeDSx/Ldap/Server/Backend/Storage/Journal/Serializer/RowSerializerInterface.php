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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal\Serializer;

/**
 * Encodes a primitive journal row to a single stored line and back.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface RowSerializerInterface
{
    /**
     * Encode a row to a single line with no embedded newline.
     *
     * @param array<string, int|string|null> $row
     */
    public function encode(array $row): string;

    /**
     * Decode a stored line back to a row, or null when it is corrupt and should be skipped.
     *
     * @return array<array-key, mixed>|null
     */
    public function decode(string $line): ?array;
}
