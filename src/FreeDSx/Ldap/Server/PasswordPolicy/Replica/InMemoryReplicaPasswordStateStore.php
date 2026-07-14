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
 * Holds replica-observed password-policy state in memory.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class InMemoryReplicaPasswordStateStore implements ReplicaPasswordStateStoreInterface
{
    /**
     * @var array<string, ReplicaPasswordState>
     */
    private array $states = [];

    public function load(Dn $dn): ReplicaPasswordState
    {
        return $this->states[$this->key($dn)]
            ?? ReplicaPasswordState::empty();
    }

    /**
     * @param callable(ReplicaPasswordState): OperationalChanges $merge
     */
    public function atomicMutate(
        Dn $dn,
        callable $merge,
    ): void {
        $key = $this->key($dn);
        $current = $this->states[$key] ?? ReplicaPasswordState::empty();
        $changes = $merge($current);
        if ($changes->isEmpty()) {
            return;
        }

        $state = $current->withChanges($changes);
        if ($state->isEmpty()) {
            unset($this->states[$key]);

            return;
        }

        $this->states[$key] = $state;
    }

    private function key(Dn $dn): string
    {
        return $dn->normalize()->toString();
    }
}
