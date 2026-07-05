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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;

/**
 * Discards automated system operational changes so a read-only replica does not persist them locally.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class NullSystemChangeWriter implements SystemChangeWriterInterface
{
    public function write(
        Dn $dn,
        OperationalChanges $changes,
    ): void {}
}
