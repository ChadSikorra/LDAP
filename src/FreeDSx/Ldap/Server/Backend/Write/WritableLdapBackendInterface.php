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

namespace FreeDSx\Ldap\Server\Backend\Write;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;

/**
 * Full-CRUD backend contract (read + write dispatch + subtree delete); implement EntryStorageInterface instead unless you must own all LDAP semantics yourself.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface WritableLdapBackendInterface extends LdapBackendInterface, WriteHandlerInterface
{
    /**
     * Delete the entry and every descendant.
     *
     * @param callable(Dn): void $authorize Throws OperationException to deny removal of the given entry.
     * @throws OperationException
     */
    public function deleteSubtree(
        DeleteCommand $command,
        WriteContext $context,
        callable $authorize,
    ): void;

    /**
     * Atomically re-read the entry, derive modifications from its current state via $compute, and apply them under an
     * exclusive entry lock.
     *
     * This is so a concurrent writer cannot clobber within a read-modify-write.
     *
     * @param callable(Entry): list<Change> $compute
     * @throws OperationException
     */
    public function atomicUpdate(
        Dn $dn,
        WriteContext $context,
        callable $compute,
    ): void;
}
