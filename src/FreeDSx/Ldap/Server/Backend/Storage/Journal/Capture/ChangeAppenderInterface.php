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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture;

use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;

/**
 * Accepts a change within the active write boundary.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ChangeAppenderInterface
{
    /**
     * Append a change within the currently active write boundary.
     */
    public function appendChange(PendingChange $change): void;
}
