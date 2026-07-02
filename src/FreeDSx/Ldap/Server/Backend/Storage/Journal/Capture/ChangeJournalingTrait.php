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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit\AuditingChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;

/**
 * Shared ChangeJournalingInterface scaffolding for storage adapters.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait ChangeJournalingTrait
{
    private ?ChangeJournalInterface $journal = null;

    public function configureJournal(ChangeJournalConfig $config): void
    {
        $journal = $this->buildJournal($config);
        $this->useJournal($config->auditSink !== null
            ? new AuditingChangeJournal(
                $journal,
                $config->auditSink,
            )
            : $journal);
    }

    public function appendChange(PendingChange $change): void
    {
        $this->journal?->append($change);
    }

    public function changeJournal(): ChangeJournalInterface
    {
        if ($this->journal === null) {
            throw new InvalidArgumentException('The change journal has not been configured.');
        }

        return $this->journal;
    }

    /**
     * Build the base journal from config using this storage's own atomic primitives (array, connection, lock).
     */
    abstract protected function buildJournal(ChangeJournalConfig $config): ChangeJournalInterface;

    /**
     * Install a ready-built journal (constructor injection or configuration); set-once.
     */
    protected function useJournal(ChangeJournalInterface $journal): void
    {
        if ($this->journal !== null) {
            throw new InvalidArgumentException('The change journal has already been configured.');
        }

        $this->journal = $journal;
    }
}
