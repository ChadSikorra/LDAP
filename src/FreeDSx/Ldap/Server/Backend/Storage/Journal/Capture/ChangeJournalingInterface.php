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

use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;

/**
 * Append a change within the active write boundary.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ChangeJournalingInterface
{
    /**
     * Append a change to the journal within the currently active write boundary.
     */
    public function appendChange(PendingChange $change): void;

    /**
     * The change journal, for reading recorded changes (e.g. the RFC 4533 sync provider).
     */
    public function changeJournal(): ChangeJournalInterface;
}
