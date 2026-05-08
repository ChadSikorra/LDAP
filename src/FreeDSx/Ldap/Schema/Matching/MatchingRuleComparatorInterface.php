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

namespace FreeDSx\Ldap\Schema\Matching;

interface MatchingRuleComparatorInterface
{
    /**
     * Whether two attribute values are considered equal under this matching rule.
     */
    public function equals(
        string $a,
        string $b,
    ): bool;

    /**
     * Ordering comparison: negative if $a < $b, zero if equal, positive if $a > $b.
     */
    public function compare(
        string $a,
        string $b,
    ): int;

    /**
     * Whether $value satisfies the given substring assertion.
     */
    public function substringMatches(
        string $value,
        SubstringAssertion $assertion,
    ): bool;
}
