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

/**
 * Validates the Integer syntax (RFC 4517 §3.3.16): an optional minus sign with no leading zeros.
 *
 * e.g. "-42"
 */
final class IntegerSyntaxValidator implements SyntaxValidatorInterface
{
    public function isValid(string $value): bool
    {
        if ($value === '0') {
            return true;
        }

        $digits = str_starts_with($value, '-')
            ? substr($value, 1)
            : $value;

        return $digits !== ''
            && $digits[0] !== '0'
            && ctype_digit($digits);
    }
}
