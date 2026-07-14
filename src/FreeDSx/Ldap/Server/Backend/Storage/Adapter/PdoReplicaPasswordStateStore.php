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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoTransactor;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordState;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;

use function is_array;
use function is_string;
use function json_decode;
use function json_encode;

/**
 * Replica-local password-policy state persisted as a JSON row per subject, sharing a PdoStorage connection.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PdoReplicaPasswordStateStore implements ReplicaPasswordStateStoreInterface
{
    private const TABLE = 'ldap_replica_pwpolicy_state';

    public function __construct(private PdoTransactor $transactor) {}

    public function load(Dn $dn): ReplicaPasswordState
    {
        $statement = $this->transactor
            ->pdo()
            ->prepare('SELECT state FROM ' . self::TABLE . ' WHERE lc_dn = ?');
        $statement->execute([$this->key($dn)]);
        $state = $statement->fetchColumn();

        return is_string($state)
            ? $this->decode($state)
            : ReplicaPasswordState::empty();
    }

    /**
     * @param callable(ReplicaPasswordState): OperationalChanges $merge
     */
    public function atomicMutate(
        Dn $dn,
        callable $merge,
    ): void {
        $this->transactor->atomic(function () use ($dn, $merge): void {
            $key = $this->key($dn);
            $current = $this->load($dn);
            $changes = $merge($current);

            if ($changes->isEmpty()) {
                return;
            }

            $next = $current->withChanges($changes);

            $this->transactor
                ->pdo()
                ->prepare('DELETE FROM ' . self::TABLE . ' WHERE lc_dn = ?')
                ->execute([$key]);

            if ($next->isEmpty()) {
                return;
            }

            $this->transactor
                ->pdo()
                ->prepare('INSERT INTO ' . self::TABLE . ' (lc_dn, state) VALUES (?, ?)')
                ->execute([
                    $key,
                    $this->encode($next),
                ]);
        });
    }

    private function key(Dn $dn): string
    {
        return $dn->normalize()->toString();
    }

    private function encode(ReplicaPasswordState $state): string
    {
        $json = json_encode($state->toArray());
        if ($json === false) {
            throw new StorageIoException('Failed to encode replica password-policy state.');
        }

        return $json;
    }

    private function decode(string $state): ReplicaPasswordState
    {
        /** @var array<string, list<string>>|null $decoded */
        $decoded = json_decode(
            $state,
            true,
        );
        if (!is_array($decoded)) {
            throw new StorageIoException('Failed to decode replica password-policy state; storage row is corrupted.');
        }

        return ReplicaPasswordState::fromArray($decoded);
    }
}
