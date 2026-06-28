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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit;

use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;

/**
 * Durable destination for committed change records (file, syslog, SIEM).
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface AuditSinkInterface
{
    public function write(ChangeRecord $record): void;
}
