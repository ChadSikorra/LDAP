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

/**
 * Case-sensitive string comparator (caseExactMatch / caseExactSubstringsMatch / caseExactOrderingMatch).
 * Delegates to OctetStringComparator since both perform byte-exact comparison.
 */
final readonly class CaseExactComparator implements MatchingRuleComparatorInterface
{
    private OctetStringComparator $inner;

    public function __construct()
    {
        $this->inner = new OctetStringComparator();
    }

    public function equals(
        string $a,
        string $b,
    ): bool {
        return $this->inner->equals($a, $b);
    }

    public function compare(
        string $a,
        string $b,
    ): int {
        return $this->inner->compare($a, $b);
    }

    public function substringMatches(
        string $value,
        SubstringAssertion $assertion,
    ): bool {
        return $this->inner->substringMatches(
            $value,
            $assertion,
        );
    }
}
