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

namespace FreeDSx\Ldap\Schema\Validation\Syntax;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;

/**
 * Validates the Generalized Time syntax (RFC 4517 §3.3.13) by delegating to the canonical parser.
 *
 * e.g. "20240101123000Z"
 */
final class GeneralizedTimeSyntaxValidator implements SyntaxValidatorInterface
{
    public function isValid(string $value): bool
    {
        try {
            GeneralizedTime::parse($value);

            return true;
        } catch (InvalidArgumentException) {
            return false;
        }
    }
}
