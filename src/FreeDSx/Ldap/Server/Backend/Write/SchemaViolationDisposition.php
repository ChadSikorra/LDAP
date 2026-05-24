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

namespace FreeDSx\Ldap\Server\Backend\Write;

/**
 * How a schema violation was handled.
 */
enum SchemaViolationDisposition: string
{
    /**
     * Enforced (the write was rejected).
     */
    case Rejected = 'strict';

    /**
     * Allowed by server policy (Lenient mode).
     */
    case RelaxedByPolicy = 'lenient';

    /**
     * Allowed by the Relax Rules control on this operation.
     */
    case RelaxedByControl = 'relaxed';
}
