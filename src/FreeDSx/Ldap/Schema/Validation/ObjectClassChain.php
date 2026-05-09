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

use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Schema;

/**
 * Resolves the full MUST and MAY attribute sets by walking the object class inheritance chain.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ObjectClassChain
{
    /**
     * Lowercased canonical attribute names that are required.
     *
     * @var list<string>
     */
    public array $must;

    /**
     * Lowercased canonical attribute names that are permitted.
     *
     * @var list<string>
     */
    public array $may;

    /**
     * @param list<ObjectClass> $objectClasses
     */
    public function __construct(
        Schema $schema,
        array $objectClasses,
    ) {
        $must = [];
        $may = [];
        $visited = [];
        $queue = $objectClasses;

        while ($queue !== []) {
            $oc = array_shift($queue);

            if (isset($visited[$oc->oid])) {
                continue;
            }

            $visited[$oc->oid] = true;

            foreach ($oc->must as $name) {
                $must[] = strtolower($schema->getAttributeType($name)?->names[0] ?? $name);
            }

            foreach ($oc->may as $name) {
                $may[] = strtolower($schema->getAttributeType($name)?->names[0] ?? $name);
            }

            foreach ($oc->superClassOids as $superOid) {
                $super = $schema->getObjectClass($superOid);
                if ($super !== null) {
                    $queue[] = $super;
                }
            }
        }

        $this->must = array_values(array_unique($must));
        $this->may = array_values(array_unique($may));
    }
}
