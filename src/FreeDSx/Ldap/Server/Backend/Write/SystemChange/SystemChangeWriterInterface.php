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

namespace FreeDSx\Ldap\Server\Backend\Write\SystemChange;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;

/**
 * Persists server-generated operational changes (such as password-policy bind state) to an entry.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface SystemChangeWriterInterface
{
    /**
     * @throws OperationException
     */
    public function write(
        Dn $dn,
        OperationalChanges $changes,
    ): void;
}
