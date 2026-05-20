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

namespace FreeDSx\Ldap\Server\PasswordPolicy;

/**
 * Result of an engine "record" method: the bookkeeping deltas plus the outcome to surface.
 */
final readonly class RecordedOutcome
{
    public function __construct(
        public PasswordPolicyOutcome $outcome,
        public OperationalChanges $changes,
    ) {}
}
