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
 * Database-specific SQL for the change-journal tables.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoJournalDialectInterface
{
    /**
     * DDL for the `ldap_change_journal` table. Columns: seq (PK), origin, created_at (unix seconds),
     * change_type, dn, entry_uuid, authz_id, previous_dn (null), pre_image (null; base64 of a serialized Entry).
     */
    public function ddlCreateJournalTable(): string;

    /**
     * DDL statements creating journal indexes; empty when indexes are defined inline in ddlCreateJournalTable().
     *
     * @return list<string>
     */
    public function ddlCreateJournalIndexes(): array;

    /**
     * DDL for the single-row `ldap_change_journal_seq` counter table holding the monotonic high-water seq.
     */
    public function ddlCreateJournalSeqTable(): string;

    /**
     * Seeds the counter row (id=1, seq=0) if absent; safe to run on every initialize().
     */
    public function queryJournalSeqInit(): string;

    /**
     * Inserts one journal record. Parameters: [seq, origin, created_at, change_type, dn, entry_uuid, authz_id, previous_dn, pre_image]
     */
    public function queryJournalInsert(): string;

    /**
     * `UPDATE ldap_change_journal_seq SET seq = seq + 1 WHERE id = 1`.
     */
    public function queryJournalSeqBump(): string;

    /**
     * `SELECT seq FROM ldap_change_journal_seq WHERE id = 1` — the high-water seq.
     */
    public function queryJournalSeqRead(): string;

    /**
     * Journal records with seq greater than the bound value, ascending. Parameters: [afterSeq]
     */
    public function queryJournalReadSince(): string;

    /**
     * `SELECT MIN(seq) FROM ldap_change_journal` — the retained window floor (NULL when empty).
     */
    public function queryJournalMinSeq(): string;

    /**
     * The seq of the Nth-newest record (the smallest seq kept). Parameter bound int: [offset = keepCount - 1]
     */
    public function queryJournalKeepFloor(): string;

    /**
     * `DELETE FROM ldap_change_journal WHERE seq < ?`. Parameters: [floorSeq]
     */
    public function queryJournalDeleteBelow(): string;

    /**
     * `DELETE FROM ldap_change_journal WHERE created_at < ?`. Parameters: [cutoffUnixSeconds]
     */
    public function queryJournalDeleteByAge(): string;
}
