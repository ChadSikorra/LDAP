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

namespace FreeDSx\Ldap;

/**
 * Resolves paths to files shipped in the package's resources directory.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class Resources
{
    public static function path(string $relative): string
    {
        return dirname(__DIR__, 3)
            . '/resources/'
            . ltrim($relative, '/');
    }
}
