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

namespace FreeDSx\Ldap\Protocol\Queue\Response;

use FreeDSx\Ldap\Protocol\LdapMessageResponse;

/**
 * Observes or transforms an outgoing response before it is encoded and sent.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ResponseInterceptor
{
    /**
     * Return the response to send.
     */
    public function intercept(LdapMessageResponse $response): LdapMessageResponse;
}
