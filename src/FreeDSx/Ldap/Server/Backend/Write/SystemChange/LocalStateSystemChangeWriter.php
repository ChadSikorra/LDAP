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

namespace FreeDSx\Ldap\Server\Backend\Write\SystemChange;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;

/**
 * Records password-policy bind state to a replica-local store instead of the replicated entry.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LocalStateSystemChangeWriter implements SystemChangeWriterInterface
{
    public function __construct(private ReplicaPasswordStateStoreInterface $store) {}

    public function write(
        Dn $dn,
        OperationalChanges $changes,
    ): void {
        $this->store->apply(
            $dn,
            $changes,
        );
    }
}
