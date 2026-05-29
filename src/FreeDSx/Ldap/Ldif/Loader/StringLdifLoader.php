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

namespace FreeDSx\Ldap\Ldif\Loader;

use Generator;

use function preg_split;

/**
 * Yields LDIF lines from a string held in memory.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class StringLdifLoader implements LdifLoaderInterface
{
    public function __construct(private string $ldif) {}

    /**
     * @return Generator<string>
     */
    public function load(): Generator
    {
        $lines = preg_split(
            "/\r\n|\r|\n/",
            $this->ldif,
        );

        if ($lines === false) {
            return;
        }

        foreach ($lines as $line) {
            yield $line;
        }
    }
}
