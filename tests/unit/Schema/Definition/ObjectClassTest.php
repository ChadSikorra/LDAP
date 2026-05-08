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

namespace Tests\Unit\FreeDSx\Ldap\Schema\Definition;

use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use PHPUnit\Framework\TestCase;

final class ObjectClassTest extends TestCase
{
    public function test_description_string_structural_minimal(): void
    {
        $oc = new ObjectClass(
            oid: '2.5.6.6',
            names: ['person'],
            type: ObjectClassType::StructuralClass,
        );

        self::assertSame(
            "( 2.5.6.6 NAME 'person' STRUCTURAL )",
            $oc->toDescriptionString(),
        );
    }

    public function test_description_string_abstract(): void
    {
        $oc = new ObjectClass(
            oid: '2.5.6.0',
            names: ['top'],
            type: ObjectClassType::AbstractClass,
        );

        self::assertSame(
            "( 2.5.6.0 NAME 'top' ABSTRACT )",
            $oc->toDescriptionString(),
        );
    }

    public function test_description_string_auxiliary(): void
    {
        $oc = new ObjectClass(
            oid: '1.3.6.1.4.1.1466.344',
            names: ['dcObject'],
            type: ObjectClassType::AuxiliaryClass,
        );

        self::assertSame(
            "( 1.3.6.1.4.1.1466.344 NAME 'dcObject' AUXILIARY )",
            $oc->toDescriptionString(),
        );
    }

    public function test_description_string_with_sup_must_may(): void
    {
        $oc = new ObjectClass(
            oid: '2.5.6.6',
            names: ['person'],
            type: ObjectClassType::StructuralClass,
            superClassOids: ['top'],
            must: ['sn', 'cn'],
            may: ['description'],
            desc: 'natural persons',
        );

        self::assertSame(
            "( 2.5.6.6 NAME 'person' DESC 'natural persons' SUP top STRUCTURAL MUST ( sn \$ cn ) MAY description )",
            $oc->toDescriptionString(),
        );
    }

    public function test_description_string_with_single_sup(): void
    {
        $oc = new ObjectClass(
            oid: '2.5.6.7',
            names: ['organizationalPerson'],
            type: ObjectClassType::StructuralClass,
            superClassOids: ['person'],
        );

        self::assertSame(
            "( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL )",
            $oc->toDescriptionString(),
        );
    }

    public function test_description_string_with_obsolete(): void
    {
        $oc = new ObjectClass(
            oid: '2.5.6.6',
            names: ['person'],
            obsolete: true,
        );

        self::assertSame(
            "( 2.5.6.6 NAME 'person' OBSOLETE STRUCTURAL )",
            $oc->toDescriptionString(),
        );
    }
}
