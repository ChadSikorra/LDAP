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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal\Serializer;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Clock\EpochMicroseconds;
use Throwable;

use function base64_decode;
use function base64_encode;
use function is_array;
use function is_numeric;
use function is_scalar;
use function is_string;
use function serialize;
use function unserialize;

/**
 * Maps a ChangeRecord to a primitive, format-portable row and back; the one place field names live.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ChangeRecordRowMapper
{
    /**
     * @return array<string, int|string|null>
     */
    public function toRow(ChangeRecord $record): array
    {
        $change = $record->change;
        $normDn = $change->dn->normalize();

        return [
            'seq' => $record->seq,
            'origin' => (string) $record->origin,
            'created_at' => EpochMicroseconds::fromDateTime($record->createdAt),
            'change_type' => $change->changeType->value,
            'dn' => $change->dn->toString(),
            'lc_dn' => $normDn->toString(),
            'lc_parent_dn' => $normDn->getParent()?->toString() ?? '',
            'entry_uuid' => $change->entryUuid,
            'authz_id' => $change->authzId->toString(),
            'previous_dn' => $change->previousDn?->toString(),
            'pre_image' => $this->encodePreImage($change->preImage),
        ];
    }

    /**
     * @param array<array-key, mixed> $row
     */
    public function fromRow(array $row): ?ChangeRecord
    {
        try {
            $dn = new Dn($this->stringField($row, 'dn'));

            return new ChangeRecord(
                seq: $this->intField($row, 'seq'),
                origin: new ReplicaId($this->stringField($row, 'origin')),
                createdAt: EpochMicroseconds::toDateTime($this->intField($row, 'created_at')),
                change: new PendingChange(
                    changeType: ChangeType::from($this->stringField($row, 'change_type')),
                    dn: $dn,
                    entryUuid: $this->stringField($row, 'entry_uuid'),
                    authzId: AuthzId::fromString($this->stringField($row, 'authz_id')),
                    previousDn: is_string($row['previous_dn'] ?? null)
                        ? new Dn($this->stringField($row, 'previous_dn'))
                        : null,
                    preImage: $this->decodePreImage($row['pre_image'] ?? null, $dn),
                ),
            );
        } catch (Throwable) {
            // A structurally valid row with bad field data is skipped rather than aborting the read.
            return null;
        }
    }

    private function encodePreImage(?Entry $preImage): ?string
    {
        if ($preImage === null) {
            return null;
        }

        // base64 of a serialized attribute map keeps binary values portable across text formats in one field.
        return base64_encode(serialize($preImage->toArray()));
    }

    private function decodePreImage(
        mixed $encoded,
        Dn $dn,
    ): ?Entry {
        if (!is_string($encoded)) {
            return null;
        }

        $decoded = base64_decode($encoded, true);

        if ($decoded === false) {
            return null;
        }

        $attributes = unserialize(
            $decoded,
            ['allowed_classes' => false],
        );

        if (!is_array($attributes)) {
            return null;
        }

        /** @var array<string, list<string>> $attributes */
        return Entry::fromArray(
            $dn->toString(),
            $attributes,
        );
    }

    /**
     * @param array<array-key, mixed> $row
     */
    private function stringField(
        array $row,
        string $key,
    ): string {
        $value = $row[$key] ?? null;

        return is_scalar($value)
            ? (string) $value
            : '';
    }

    /**
     * @param array<array-key, mixed> $row
     */
    private function intField(
        array $row,
        string $key,
    ): int {
        $value = $row[$key] ?? null;

        return is_numeric($value)
            ? (int) $value
            : 0;
    }
}
