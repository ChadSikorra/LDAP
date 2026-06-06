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

namespace Tests\Support\FreeDSx\Ldap\PhpStan;

use ReflectionClassConstant;
use ReflectionEnumUnitCase;
use ReflectionMethod;
use ReflectionProperty;
use ShipMonk\PHPStan\DeadCode\Provider\ReflectionBasedMemberUsageProvider;
use ShipMonk\PHPStan\DeadCode\Provider\VirtualUsageData;

/**
 * Honors member-level @api, which the built-in provider only resolves on classes and interfaces, not traits.
 */
final class ApiMemberUsageProvider extends ReflectionBasedMemberUsageProvider
{
    protected function shouldMarkMethodAsUsed(ReflectionMethod $method): ?VirtualUsageData
    {
        return $this->markIfApi($method->getDocComment());
    }

    protected function shouldMarkConstantAsUsed(ReflectionClassConstant $constant): ?VirtualUsageData
    {
        return $this->markIfApi($constant->getDocComment());
    }

    protected function shouldMarkEnumCaseAsUsed(ReflectionEnumUnitCase $enumCase): ?VirtualUsageData
    {
        return $this->markIfApi($enumCase->getDocComment());
    }

    protected function shouldMarkPropertyAsRead(ReflectionProperty $property): ?VirtualUsageData
    {
        return $this->markIfApi($property->getDocComment());
    }

    protected function shouldMarkPropertyAsWritten(ReflectionProperty $property): ?VirtualUsageData
    {
        return $this->markIfApi($property->getDocComment());
    }

    private function markIfApi(string|false $docComment): ?VirtualUsageData
    {
        if ($docComment === false) {
            return null;
        }

        if (preg_match('/@api\b/', $docComment) !== 1) {
            return null;
        }

        return VirtualUsageData::withNote('Member marked @api');
    }
}
