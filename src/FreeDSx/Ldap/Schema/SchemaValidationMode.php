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

namespace FreeDSx\Ldap\Schema;

enum SchemaValidationMode
{
    /**
     * Reject writes that violate the schema.
     */
    case Strict;

    /**
     * Log schema violations but allow the write to proceed.
     */
    case Lenient;

    /**
     * Skip schema validation entirely.
     */
    case Off;
}
