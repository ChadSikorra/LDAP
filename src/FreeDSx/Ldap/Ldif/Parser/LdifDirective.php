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

namespace FreeDSx\Ldap\Ldif\Parser;

use function strcasecmp;

/**
 * A name/value pair read from an LDIF directive line, paired with the cursor position it started at.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LdifDirective
{
    public function __construct(
        public string $name,
        public string $value,
        public int $position,
        public ?string $sourceLine = null,
    ) {}

    /**
     * Case-insensitive comparison of the directive name.
     */
    public function is(string $name): bool
    {
        return strcasecmp($this->name, $name) === 0;
    }
}
