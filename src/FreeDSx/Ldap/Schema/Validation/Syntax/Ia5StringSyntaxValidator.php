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
 * Validates the IA5 String syntax (RFC 4517 §3.3.15): characters from the ASCII (IA5) range only.
 *
 * e.g. "user@example.com"
 */
final class Ia5StringSyntaxValidator implements SyntaxValidatorInterface
{
    public function isValid(string $value): bool
    {
        return mb_check_encoding(
            $value,
            'ASCII',
        );
    }
}
