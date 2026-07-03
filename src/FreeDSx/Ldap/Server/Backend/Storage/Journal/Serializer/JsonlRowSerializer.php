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

use function is_array;
use function json_decode;
use function json_encode;

/**
 * JSON-lines row format: one JSON object per line.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class JsonlRowSerializer implements RowSerializerInterface
{
    public function encode(array $row): string
    {
        return json_encode(
            $row,
            JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR,
        );
    }

    public function decode(string $line): ?array
    {
        $row = json_decode($line, true);

        return is_array($row)
            ? $row
            : null;
    }
}
