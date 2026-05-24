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

use FreeDSx\Ldap\Entry\Dn;

/**
 * Validates the Distinguished Name syntax (RFC 4517 §3.3.9) by parsing the value as a DN.
 *
 * e.g. "cn=Alice,dc=example,dc=com"
 */
final class DistinguishedNameSyntaxValidator implements SyntaxValidatorInterface
{
    public function isValid(string $value): bool
    {
        return Dn::isValid($value);
    }
}
