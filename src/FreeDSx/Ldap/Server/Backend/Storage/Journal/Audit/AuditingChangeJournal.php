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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit;

use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionPolicy;
use FreeDSx\Ldap\Server\Logging\ExceptionLogging;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Throwable;

/**
 * Decorates a journal to tee each appended record to an audit sink; read/prune pass through.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class AuditingChangeJournal implements ChangeJournalInterface
{
    public function __construct(
        private readonly ChangeJournalInterface $journal,
        private readonly AuditSinkInterface $sink,
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {}

    public function append(PendingChange $change): ChangeRecord
    {
        $record = $this->journal->append($change);

        // The journal already holds the record, so a failed export is logged, not fatal: the write
        // still succeeds and the record can be re-exported from the journal later.
        try {
            $this->sink->write($record);
        } catch (Throwable $e) {
            $this->logger->error(
                'Failed to write a change record to the audit sink.',
                ExceptionLogging::makeLogContext($e),
            );
        }

        return $record;
    }

    public function read(int $afterSeq = 0): iterable
    {
        return $this->journal->read($afterSeq);
    }

    public function latestSeq(): int
    {
        return $this->journal->latestSeq();
    }

    public function prune(RetentionPolicy $policy): int
    {
        return $this->journal->prune($policy);
    }
}
