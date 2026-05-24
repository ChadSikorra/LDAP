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
 * Validates that a single attribute value conforms to an LDAP syntax (RFC 4517).
 */
interface SyntaxValidatorInterface
{
    /**
     * Whether the given attribute value conforms to this LDAP syntax.
     */
    public function isValid(string $value): bool;
}
