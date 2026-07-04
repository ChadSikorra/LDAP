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

namespace FreeDSx\Ldap\Server\Clock;

/**
 * Pauses execution for a duration, cooperating with the runner.
 */
interface Sleeper
{
    public function sleep(float $seconds): void;
}
