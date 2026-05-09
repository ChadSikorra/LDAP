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
 * The three components of an LDAP substring filter assertion.
 */
final readonly class SubstringAssertion
{
    /**
     * @param list<string> $any
     */
    public function __construct(
        public ?string $initial = null,
        public array $any = [],
        public ?string $final = null,
    ) {}
}
