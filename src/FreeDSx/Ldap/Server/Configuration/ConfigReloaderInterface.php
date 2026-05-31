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

namespace FreeDSx\Ldap\Server\Configuration;

use FreeDSx\Ldap\ServerOptions;

/**
 * Produces the ServerOptions to use going forward when the server is asked to reload (e.g. on SIGHUP).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ConfigReloaderInterface
{
    /**
     * Returns the options the server should adopt for new connections. In-flight connections keep their current options.
     */
    public function reload(ServerOptions $current): ServerOptions;
}
