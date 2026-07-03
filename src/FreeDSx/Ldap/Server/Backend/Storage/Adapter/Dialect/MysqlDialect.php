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

/**
 * MySQL/MariaDB SQL for PdoStorage; requires MySQL 8.0+ or MariaDB 10.6+.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class MysqlDialect implements PdoDialectInterface
{
    use PdoDialectTrait;
    use PdoJournalDialectTrait;

    /**
     * DN columns are 768 chars — the maximum that still fits an InnoDB index.
     */
    public function ddlCreateTable(): string
    {
        return <<<SQL
            CREATE TABLE IF NOT EXISTS entries (
                lc_dn         VARCHAR(768) NOT NULL,
                dn            VARCHAR(768) NOT NULL,
                lc_parent_dn  VARCHAR(768) NOT NULL DEFAULT '',
                attributes    LONGBLOB NOT NULL,
                PRIMARY KEY (lc_dn),
                INDEX idx_lc_parent_dn (lc_parent_dn)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        SQL;
    }

    /**
     * @inheritDoc Inline with ddlCreateTable().
     */
    public function ddlCreateIndex(): ?string
    {
        return null;
    }

    /**
     * entry_lc_dn collation matches entries.lc_dn (FK requirement); value_lower uses utf8mb4_bin so pre-lowered values compare byte-wise.
     */
    public function ddlCreateSidecarTable(): string
    {
        return <<<SQL
            CREATE TABLE IF NOT EXISTS entry_attribute_values (
                entry_lc_dn      VARCHAR(768) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
                attr_name_lower  VARCHAR(255) NOT NULL,
                value_lower      VARCHAR(255) NOT NULL,
                value_original   TEXT NOT NULL,
                INDEX idx_eav_attr_value (attr_name_lower, value_lower),
                INDEX idx_eav_entry (entry_lc_dn),
                CONSTRAINT fk_eav_entry FOREIGN KEY (entry_lc_dn)
                    REFERENCES entries(lc_dn) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
        SQL;
    }

    /**
     * @inheritDoc Inline with ddlCreateSidecarTable().
     */
    public function ddlCreateSidecarIndexes(): array
    {
        return [];
    }

    /**
     * @todo Replace VALUES() with row alias syntax once MariaDB supports it.
     */
    public function queryUpsert(): string
    {
        return <<<SQL
            INSERT INTO entries (lc_dn, dn, lc_parent_dn, attributes)
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                dn = VALUES(dn),
                lc_parent_dn = VALUES(lc_parent_dn),
                attributes = VALUES(attributes)
        SQL;
    }

    public function maxDnLength(): int
    {
        return 768;
    }

    public function ddlCreateJournalTable(): string
    {
        return <<<SQL
            CREATE TABLE IF NOT EXISTS ldap_change_journal (
                seq          BIGINT NOT NULL,
                origin       VARCHAR(255) NOT NULL,
                created_at   BIGINT NOT NULL,
                change_type  VARCHAR(16) NOT NULL,
                dn           TEXT NOT NULL,
                lc_dn        VARCHAR(768) NOT NULL,
                lc_parent_dn VARCHAR(768) NOT NULL DEFAULT '',
                entry_uuid   VARCHAR(255) NOT NULL,
                authz_id     TEXT NOT NULL,
                previous_dn  TEXT,
                pre_image    LONGBLOB,
                PRIMARY KEY (seq),
                INDEX idx_journal_created_at (created_at),
                INDEX idx_journal_lc_dn (lc_dn),
                INDEX idx_journal_lc_parent_dn (lc_parent_dn)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        SQL;
    }

    public function ddlCreateJournalIndexes(): array
    {
        return [];
    }

    public function ddlCreateJournalSeqTable(): string
    {
        return <<<SQL
            CREATE TABLE IF NOT EXISTS ldap_change_journal_seq (
                id   INT NOT NULL,
                seq  BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        SQL;
    }

    public function queryJournalSeqInit(): string
    {
        return 'INSERT IGNORE INTO ldap_change_journal_seq (id, seq) VALUES (1, 0)';
    }
}
