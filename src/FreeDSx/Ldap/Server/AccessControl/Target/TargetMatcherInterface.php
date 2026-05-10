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

namespace FreeDSx\Ldap\Server\AccessControl\Target;

use FreeDSx\Ldap\Entry\Dn;

/**
 * Determines whether a target DN matches a rule target.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface TargetMatcherInterface
{
    public function matches(Dn $dn): bool;
}
