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

namespace FreeDSx\Ldap\Schema\Validation;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\AttributeUsage;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;

/**
 * Validates entries against the schema for add and modify operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SchemaValidator
{
    private const EXTENSIBLE_OBJECT = 'extensibleObject';

    public function __construct(
        private readonly Schema $schema,
        private readonly SchemaValidationMode $mode,
    ) {
    }

    /**
     * Validates an entry before it is added to storage.
     *
     * @throws OperationException
     */
    public function validateAdd(Entry $entry): void
    {
        if ($this->mode === SchemaValidationMode::Off) {
            return;
        }

        $this->checkNoUserModificationInEntry($entry);
        $this->validateStructure($entry);
    }

    /**
     * Validates the changes and resulting entry from an update operation.
     *
     * @throws OperationException
     */
    public function validateModify(
        UpdateCommand $command,
        Entry $result,
    ): void {
        if ($this->mode === SchemaValidationMode::Off) {
            return;
        }

        $this->checkNoUserModificationInChanges($command->changes);
        $this->validateStructure($result);
    }

    /**
     * @throws OperationException
     */
    private function validateStructure(Entry $entry): void
    {
        if ($this->hasExtensibleObject($entry)) {
            $this->checkSingleValuedAttributes($entry);

            return;
        }

        $objectClasses = $this->collectObjectClasses($entry);

        $this->checkStructuralClass($entry, $objectClasses);
        $chain = new ObjectClassChain($this->schema, $objectClasses);
        $this->checkRequiredAttributes($entry, $chain->must);
        $this->checkAllowedAttributes($entry, $chain->must, $chain->may);
        $this->checkSingleValuedAttributes($entry);
    }

    private function hasExtensibleObject(Entry $entry): bool
    {
        foreach ($entry->get('objectClass')?->getValues() ?? [] as $oc) {
            if (strcasecmp($oc, self::EXTENSIBLE_OBJECT) === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<ObjectClass>
     */
    private function collectObjectClasses(Entry $entry): array
    {
        return array_values(array_filter(
            array_map(
                fn (string $name) => $this->schema->getObjectClass($name),
                $entry->get('objectClass')?->getValues() ?? [],
            ),
        ));
    }

    /**
     * @param list<ObjectClass> $objectClasses
     * @throws OperationException
     */
    private function checkStructuralClass(
        Entry $entry,
        array $objectClasses,
    ): void {
        foreach ($objectClasses as $oc) {
            if ($oc->type === ObjectClassType::StructuralClass) {
                return;
            }
        }

        $this->fail(
            sprintf(
                'Entry "%s" must have at least one structural object class.',
                $entry->getDn()->toString(),
            ),
            ResultCode::OBJECT_CLASS_VIOLATION,
        );
    }

    /**
     * @param list<string> $must
     * @throws OperationException
     */
    private function checkRequiredAttributes(
        Entry $entry,
        array $must,
    ): void {
        $entryNames = $this->buildEntryAttrSet($entry);

        foreach ($must as $required) {
            if (isset($entryNames[$required])) {
                continue;
            }

            $this->fail(
                sprintf('Required attribute "%s" is missing.', $required),
                ResultCode::OBJECT_CLASS_VIOLATION,
            );
        }
    }

    /**
     * @param list<string> $must
     * @param list<string> $may
     * @throws OperationException
     */
    private function checkAllowedAttributes(
        Entry $entry,
        array $must,
        array $may,
    ): void {
        $allowed = array_flip(array_merge($must, $may));

        foreach ($entry->getAttributes() as $attr) {
            $attrType = $this->schema->getAttributeType($attr->getName());

            if ($attrType === null) {
                $this->fail(
                    sprintf('Undefined attribute type: "%s".', $attr->getName()),
                    ResultCode::UNDEFINED_ATTRIBUTE_TYPE,
                );

                continue;
            }

            if ($attrType->usage !== AttributeUsage::UserApplications) {
                continue;
            }

            if (isset($allowed[strtolower($attrType->names[0] ?? $attr->getName())])) {
                continue;
            }

            $this->fail(
                sprintf('Attribute "%s" is not permitted by any object class.', $attr->getName()),
                ResultCode::OBJECT_CLASS_VIOLATION,
            );
        }
    }

    /**
     * @throws OperationException
     */
    private function checkSingleValuedAttributes(Entry $entry): void
    {
        foreach ($entry->getAttributes() as $attr) {
            $attrType = $this->schema->getAttributeType($attr->getName());
            if ($attrType === null || !$attrType->singleValue) {
                continue;
            }

            if (count($attr->getValues()) <= 1) {
                continue;
            }

            $this->fail(
                sprintf(
                    'Attribute "%s" is single-valued but has %d values.',
                    $attr->getName(),
                    count($attr->getValues()),
                ),
                ResultCode::CONSTRAINT_VIOLATION,
            );
        }
    }

    /**
     * @throws OperationException
     */
    private function checkNoUserModificationInEntry(Entry $entry): void
    {
        foreach ($entry->getAttributes() as $attr) {
            $attrType = $this->schema->getAttributeType($attr->getName());
            if ($attrType === null || !$attrType->noUserModification) {
                continue;
            }

            $this->fail(
                sprintf('Attribute "%s" cannot be set by users.', $attr->getName()),
                ResultCode::CONSTRAINT_VIOLATION,
            );
        }
    }

    /**
     * @param Change[] $changes
     * @throws OperationException
     */
    private function checkNoUserModificationInChanges(array $changes): void
    {
        foreach ($changes as $change) {
            $attrType = $this->schema->getAttributeType($change->getAttribute()->getName());
            if ($attrType === null || !$attrType->noUserModification) {
                continue;
            }

            $this->fail(
                sprintf('Attribute "%s" cannot be modified by users.', $change->getAttribute()->getName()),
                ResultCode::CONSTRAINT_VIOLATION,
            );
        }
    }

    /**
     * @return array<string, true>
     */
    private function buildEntryAttrSet(Entry $entry): array
    {
        $result = [];

        foreach ($entry->getAttributes() as $attr) {
            $attrType = $this->schema->getAttributeType($attr->getName());
            $result[strtolower($attrType?->names[0] ?? $attr->getName())] = true;
        }

        return $result;
    }

    /**
     * @throws OperationException
     */
    private function fail(
        string $message,
        int $code,
    ): void {
        throw new OperationException(
            $message,
            $code,
        );
    }
}
