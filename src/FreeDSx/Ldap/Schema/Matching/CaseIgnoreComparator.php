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
 * Case-insensitive string comparator (caseIgnoreMatch / caseIgnoreSubstringsMatch / caseIgnoreOrderingMatch).
 */
final class CaseIgnoreComparator implements MatchingRuleComparatorInterface
{
    public function equals(
        string $a,
        string $b,
    ): bool {
        return strtolower($a) === strtolower($b);
    }

    public function compare(
        string $a,
        string $b,
    ): int {
        return strcasecmp(
            $a,
            $b,
        );
    }

    public function substringMatches(
        string $value,
        SubstringAssertion $assertion,
    ): bool {
        $lower = strtolower($value);

        if ($assertion->initial !== null && !str_starts_with($lower, strtolower($assertion->initial))) {
            return false;
        }

        $pos = $assertion->initial !== null ? strlen($assertion->initial) : 0;

        foreach ($assertion->any as $substr) {
            $found = stripos($lower, strtolower($substr), $pos);
            if ($found === false) {
                return false;
            }
            $pos = $found + strlen($substr);
        }

        return $assertion->final === null
            || str_ends_with($lower, strtolower($assertion->final));
    }
}
