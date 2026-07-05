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

use PDO;

/**
 * SQLite-specific SQL for PdoStorage.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SqliteDialect implements PdoDialectInterface
{
    use PdoDialectTrait;
    use PdoJournalDialectTrait;
    use PdoSchemaTrait;

    /**
     * `BEGIN IMMEDIATE` acquires the reserved lock up front so concurrent writers wait (honoring `busy_timeout`)
     * instead of racing, which returns SQLITE_BUSY immediately to avoid deadlock.
     */
    public function beginTransaction(PDO $pdo): void
    {
        $pdo->exec('BEGIN IMMEDIATE');
    }

    public function commit(PDO $pdo): void
    {
        $pdo->exec('COMMIT');
    }

    public function rollBack(PDO $pdo): void
    {
        $pdo->exec('ROLLBACK');
    }

    public function queryUpsert(): string
    {
        return <<<SQL
            INSERT OR REPLACE
            INTO entries (lc_dn, dn, lc_parent_dn, attributes)
            VALUES (?, ?, ?, ?)
        SQL;
    }

    public function maxDnLength(): ?int
    {
        return null;
    }

    public function sortKeyClause(
        string $attributeLower,
        string $direction,
    ): SortClause {
        // RFC 2891 §2.2: NULL is the largest value, so missing entries sort last (ASC) or first (DESC).
        $nulls = $direction === 'ASC'
            ? 'NULLS LAST'
            : 'NULLS FIRST';

        return new SortClause(
            <<<SQL
                (SELECT MIN(eav.value_lower)
                 FROM entry_attribute_values eav
                 WHERE eav.entry_lc_dn = LOWER(dn)
                   AND eav.attr_name_lower = ?) $direction $nulls
            SQL,
            [$attributeLower],
        );
    }

    protected function schemaName(): string
    {
        return 'sqlite';
    }
}
