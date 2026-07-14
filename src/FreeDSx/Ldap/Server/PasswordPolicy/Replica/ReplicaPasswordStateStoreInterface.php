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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Replica;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;

/**
 * Persists replica-observed password-policy bind state locally, separate from replicated entries.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ReplicaPasswordStateStoreInterface
{
    /**
     * The locally tracked state for a subject, or an empty state when none has been recorded.
     */
    public function load(Dn $dn): ReplicaPasswordState;

    /**
     * Atomically read the subject's current local state, derive changes from it via $merge, and apply them under an
     * exclusive lock so concurrent binds cannot lose an update.
     *
     * @param callable(ReplicaPasswordState): OperationalChanges $merge
     */
    public function atomicMutate(
        Dn $dn,
        callable $merge,
    ): void;
}
