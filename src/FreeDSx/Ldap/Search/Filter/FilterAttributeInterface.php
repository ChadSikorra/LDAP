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

namespace FreeDSx\Ldap\Search\Filter;

/**
 * A filter that asserts against a single attribute type.
 */
interface FilterAttributeInterface
{
    /**
     * The attribute type the filter references, or null when it is unspecified (an extensibleMatch without one).
     */
    public function getAttribute(): ?string;
}
