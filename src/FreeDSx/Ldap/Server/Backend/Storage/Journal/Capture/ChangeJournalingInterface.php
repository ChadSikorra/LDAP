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

use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;

/**
 * A storage adapter that owns a configurable change journal.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ChangeJournalingInterface extends ChangeAppenderInterface
{
    /**
     * Build the journal from central config using the storage's own atomic primitives; set-once at wiring time.
     */
    public function configureJournal(ChangeJournalConfig $config): void;

    /**
     * The change journal, for reading recorded changes (e.g. the RFC 4533 sync provider).
     */
    public function changeJournal(): ChangeJournalInterface;
}
