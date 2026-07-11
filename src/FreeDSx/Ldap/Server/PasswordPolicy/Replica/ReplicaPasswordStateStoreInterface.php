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
     * Apply engine-emitted operational deltas to the subject's locally tracked state.
     */
    public function apply(
        Dn $dn,
        OperationalChanges $changes,
    ): void;
}
