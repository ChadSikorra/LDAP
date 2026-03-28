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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;

/**
 * Contract for the read side of a storage backend.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ReadableStorageAdapterInterface
{
    /**
     * Retrieve a single entry by its DN, or null if it does not exist.
     */
    public function get(Dn $dn): ?Entry;

    /**
     * Return all candidate entries within the given scope beneath the base DN.
     *
     * The caller is responsible for applying any filter logic to the returned set.
     * Implementations may pre-filter if they are able to do so efficiently
     * (e.g. SQL adapters pushing predicates to the database).
     *
     * @param int $scope One of the SearchRequest::SCOPE_* constants
     */
    public function list(Dn $baseDn, int $scope): Entries;

    /**
     * Verify the password for the entry identified by the given DN.
     *
     * Returns true if the password matches, false otherwise.
     */
    public function verifyPassword(Dn $dn, string $password): bool;
}
