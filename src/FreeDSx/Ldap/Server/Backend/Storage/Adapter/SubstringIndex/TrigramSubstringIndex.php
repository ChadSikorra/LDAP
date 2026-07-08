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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;

/**
 * Portable substring index: a generic trigram table usable across every PDO dialect.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class TrigramSubstringIndex implements SubstringIndexInterface
{
    /**
     * Attributes indexed by default: the common name/identity attributes typically searched by substring.
     *
     * @var list<string>
     */
    public const DEFAULT_ATTRIBUTES = [
        'cn',
        'sn',
        'givenName',
        'displayName',
        'uid',
        'mail',
        'ou',
    ];

    private const SCHEMA_NAME = 'trigram';

    private const DELETE_SQL = <<<SQL
        DELETE FROM entry_attribute_trigrams
        WHERE entry_lc_dn = ?
        SQL;

    private const INSERT_SQL = <<<SQL
        INSERT INTO entry_attribute_trigrams (entry_lc_dn, attr_name_lower, trigram)
        VALUES %s
        SQL;

    /**
     * @var array<string, true> Indexed attribute names, lowercased.
     */
    private readonly array $attributes;

    /**
     * @param list<string> $attributes
     */
    public function __construct(array $attributes = self::DEFAULT_ATTRIBUTES)
    {
        $set = [];

        foreach ($attributes as $attribute) {
            $set[strtolower($attribute)] = true;
        }

        $this->attributes = $set;
    }

    public function schemaStatements(PdoDialectInterface $dialect): array
    {
        return $dialect->schemaStatementsNamed(self::SCHEMA_NAME);
    }

    public function maintain(
        string $lcDn,
        Entry $entry,
        callable $execute,
    ): void {
        $execute(
            self::DELETE_SQL,
            [$lcDn],
        );

        $rows = $this->rowsFor($lcDn, $entry);
        if ($rows === []) {
            return;
        }

        $execute(
            sprintf(
                self::INSERT_SQL,
                $this->placeholders(count($rows)),
            ),
            $this->flatten($rows),
        );
    }

    /**
     * @return list<array{0: string, 1: string, 2: string}>
     */
    private function rowsFor(
        string $lcDn,
        Entry $entry,
    ): array {
        $rows = [];

        foreach ($entry->getAttributes() as $attribute) {
            $attrLower = strtolower($attribute->getName());
            if (!isset($this->attributes[$attrLower])) {
                continue;
            }

            $trigrams = [];
            foreach ($attribute->getValues() as $value) {
                foreach (Trigrams::of($value) as $trigram) {
                    $trigrams[] = $trigram;
                }
            }

            foreach (array_unique($trigrams) as $trigram) {
                $rows[] = [$lcDn, $attrLower, $trigram];
            }
        }

        return $rows;
    }

    private function placeholders(int $count): string
    {
        return implode(
            ', ',
            array_fill(
                0,
                $count,
                '(?, ?, ?)',
            ),
        );
    }

    /**
     * @param list<array{0: string, 1: string, 2: string}> $rows
     *
     * @return list<string>
     */
    private function flatten(array $rows): array
    {
        $params = [];

        foreach ($rows as $row) {
            $params[] = $row[0];
            $params[] = $row[1];
            $params[] = $row[2];
        }

        return $params;
    }
}
