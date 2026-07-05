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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect;

use FreeDSx\Ldap\Exception\RuntimeException;

use function explode;
use function file_get_contents;
use function sprintf;
use function trim;

/**
 * Reads a baseline schema .sql file and splits it into executable statements.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SchemaFile
{
    public function __construct(private string $path) {}

    public function sql(): string
    {
        $sql = @file_get_contents($this->path);

        if ($sql === false) {
            throw new RuntimeException(sprintf(
                'Unable to read the schema file "%s".',
                $this->path,
            ));
        }

        return $sql;
    }

    /**
     * @return list<string>
     */
    public function statements(): array
    {
        return self::split($this->sql());
    }

    /**
     * Split a schema script into statements. The baseline is authored one `;`-terminated statement per block; no
     * statement contains a `;` in a literal, so a boundary split is sufficient.
     *
     * @return list<string>
     */
    public static function split(string $sql): array
    {
        $statements = [];

        foreach (explode(';', $sql) as $statement) {
            $statement = trim($statement);

            if ($statement !== '') {
                $statements[] = $statement;
            }
        }

        return $statements;
    }
}
