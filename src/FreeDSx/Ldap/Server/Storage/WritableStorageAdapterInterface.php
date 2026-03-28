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

namespace FreeDSx\Ldap\Server\Storage;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;

/**
 * Contract for the write side of a storage backend.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface WritableStorageAdapterInterface
{
    /**
     * Add a new entry to the directory.
     */
    public function add(Entry $entry): void;

    /**
     * Delete the entry identified by the given DN.
     */
    public function delete(Dn $dn): void;

    /**
     * Apply a set of attribute changes to the entry identified by the given DN.
     *
     * @param Change[] $changes
     */
    public function update(Dn $dn, array $changes): void;

    /**
     * Rename or move an entry.
     *
     * @param Dn   $dn           The current DN of the entry.
     * @param Rdn  $newRdn       The new RDN component.
     * @param bool $deleteOldRdn Whether to remove the old RDN attribute value.
     * @param Dn|null $newParent The new parent DN, or null to keep the current parent.
     */
    public function move(
        Dn $dn,
        Rdn $newRdn,
        bool $deleteOldRdn,
        ?Dn $newParent,
    ): void;
}
