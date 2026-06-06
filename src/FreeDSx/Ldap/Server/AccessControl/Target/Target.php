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

namespace FreeDSx\Ldap\Server\AccessControl\Target;

/**
 * Factory for common target matchers.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class Target
{
    private function __construct() {}

    /**
     * Matches any target DN.
     */
    public static function any(): TargetMatcherInterface
    {
        return new AnyTargetMatcher();
    }

    /**
     * Matches a specific target DN (case-insensitive).
     */
    public static function dn(string $dn): TargetMatcherInterface
    {
        return new DnTargetMatcher($dn);
    }

    /**
     * Matches any target DN within the given subtree (case-insensitive).
     */
    public static function subtree(string $dn): TargetMatcherInterface
    {
        return new SubtreeTargetMatcher($dn);
    }
}
