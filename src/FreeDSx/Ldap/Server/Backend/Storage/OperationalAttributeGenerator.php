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

namespace FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

/**
 * Injects server-managed operational attributes into entries on write.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class OperationalAttributeGenerator
{
    public function __construct(
        private readonly ?Schema $schema = null,
    ) {}

    /**
     * Sets createTimestamp, modifyTimestamp, creatorsName, modifiersName, entryUUID, and structuralObjectClass.
     */
    public function applyForAdd(
        Entry $entry,
        WriteContext $context,
    ): void {
        $timestamp = $this->generateTimestamp();
        $boundDn = $context->getBoundDn() ?? '';

        $entry->set(
            AttributeTypeOid::NAME_CREATE_TIMESTAMP,
            $timestamp,
        );
        $entry->set(
            AttributeTypeOid::NAME_MODIFY_TIMESTAMP,
            $timestamp,
        );
        $entry->set(
            AttributeTypeOid::NAME_CREATORS_NAME,
            $boundDn,
        );
        $entry->set(
            AttributeTypeOid::NAME_MODIFIERS_NAME,
            $boundDn,
        );
        $entry->set(
            AttributeTypeOid::NAME_ENTRY_UUID,
            $this->generateUuid(),
        );

        $structuralOc = $this->resolveStructuralObjectClass($entry);

        if ($structuralOc !== null) {
            $entry->set(
                AttributeTypeOid::NAME_STRUCTURAL_OBJECT_CLASS,
                $structuralOc,
            );
        }
    }

    /**
     * Updates modifyTimestamp and modifiersName only.
     */
    public function applyForModify(
        Entry $entry,
        WriteContext $context,
    ): void {
        $entry->set(
            AttributeTypeOid::NAME_MODIFY_TIMESTAMP,
            $this->generateTimestamp(),
        );
        $entry->set(
            AttributeTypeOid::NAME_MODIFIERS_NAME,
            $context->getBoundDn() ?? '',
        );
    }

    private function generateTimestamp(): string
    {
        return gmdate('YmdHis') . 'Z';
    }

    private function generateUuid(): string
    {
        $bytes = random_bytes(16);

        // Set version 4 and RFC 4122 variant bits.
        $bytes[6] = chr(ord($bytes[6]) & 0x0f | 0x40);
        $bytes[8] = chr(ord($bytes[8]) & 0x3f | 0x80);

        return vsprintf(
            '%s%s-%s-%s-%s-%s%s%s',
            str_split(
                bin2hex($bytes),
                4,
            ),
        );
    }

    private function resolveStructuralObjectClass(Entry $entry): ?string
    {
        if ($this->schema === null) {
            return null;
        }

        $objectClassAttr = $entry->get(
            'objectClass',
            true,
        );

        if ($objectClassAttr === null) {
            return null;
        }

        $structural = $this->collectStructuralClasses(
            $this->schema,
            $objectClassAttr->getValues(),
        );

        if ($structural === []) {
            return null;
        }

        foreach ($structural as $candidate) {
            if (!$this->isSuperclassOfAny($candidate, $structural, $this->schema)) {
                return $candidate->names[0] ?? $candidate->oid;
            }
        }

        $first = array_values($structural)[0];

        return $first->names[0] ?? $first->oid;
    }

    /**
     * @param string[] $names
     * @return array<string, ObjectClass>
     */
    private function collectStructuralClasses(
        Schema $schema,
        array $names,
    ): array {
        $structural = [];

        foreach ($names as $name) {
            $oc = $schema->getObjectClass($name);

            if ($oc === null || $oc->type !== ObjectClassType::StructuralClass) {
                continue;
            }

            $structural[$oc->oid] = $oc;
        }

        return $structural;
    }

    /**
     * @param array<string, ObjectClass> $structural
     */
    private function isSuperclassOfAny(
        ObjectClass $candidate,
        array $structural,
        Schema $schema,
    ): bool {
        foreach ($structural as $other) {
            if ($other->oid === $candidate->oid) {
                continue;
            }

            if ($this->isDirectSuperclassOf($candidate, $other, $schema)) {
                return true;
            }
        }

        return false;
    }

    private function isDirectSuperclassOf(
        ObjectClass $candidate,
        ObjectClass $other,
        Schema $schema,
    ): bool {
        foreach ($other->superClassOids as $superOid) {
            $resolved = $schema->getObjectClass($superOid);

            if ($resolved !== null && $resolved->oid === $candidate->oid) {
                return true;
            }
        }

        return false;
    }
}
