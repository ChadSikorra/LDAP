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
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;

use function count;

/**
 * Holds replica-observed password-policy state in memory, with a per-subject forward watermark.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class InMemoryReplicaPasswordStateStore implements ReplicaPasswordStateStoreInterface
{
    /**
     * @var array<string, ReplicaForwardState>
     */
    private array $records = [];

    public function load(Dn $dn): ReplicaPasswordState
    {
        return ($this->records[$this->key($dn)] ?? ReplicaForwardState::initial($dn))->state;
    }

    /**
     * @param callable(ReplicaPasswordState): OperationalChanges $merge
     */
    public function atomicMutate(
        Dn $dn,
        callable $merge,
    ): void {
        $key = $this->key($dn);
        $record = $this->records[$key] ?? ReplicaForwardState::initial($dn);
        $changes = $merge($record->state);

        if ($changes->isEmpty()) {
            return;
        }

        $next = $record->state->withChanges($changes);
        if ($record->state->equals($next)) {
            return;
        }

        $this->records[$key] = $record->applied($next);
    }

    public function listUnforwarded(int $limit = 100): array
    {
        $pending = [];

        foreach ($this->records as $record) {
            if (!$record->isPending()) {
                continue;
            }

            $pending[] = $record;
            if (count($pending) >= $limit) {
                break;
            }
        }

        return $pending;
    }

    public function markForwarded(
        Dn $dn,
        int $sequence,
    ): void {
        $key = $this->key($dn);
        $record = $this->records[$key] ?? null;

        if ($record === null || !$record->canAdvanceTo($sequence)) {
            return;
        }

        $this->records[$key] = $record->advancedTo($sequence);
    }

    public function discardIfSuperseded(
        Dn $dn,
        UserPasswordState $authoritative,
    ): void {
        $key = $this->key($dn);
        $record = $this->records[$key] ?? null;
        if ($record === null) {
            return;
        }

        if ($record->state->toUserPasswordState($dn)->isSupersededBy($authoritative)) {
            unset($this->records[$key]);
        }
    }

    public function discard(Dn $dn): void
    {
        unset($this->records[$this->key($dn)]);
    }

    private function key(Dn $dn): string
    {
        return $dn->normalize()->toString();
    }
}
