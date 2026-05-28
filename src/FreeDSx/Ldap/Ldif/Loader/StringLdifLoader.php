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

/**
 * Loads LDIF text held in memory as a string.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class StringLdifLoader implements LdifLoaderInterface
{
    public function __construct(private string $ldif) {}

    public function load(): string
    {
        return $this->ldif;
    }
}
