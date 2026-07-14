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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Replica\Forward;

use FreeDSx\Ldap\Operation\Request\ForwardPasswordPolicyStateRequest;

/**
 * Delivers a replica's password-policy forward request to the primary over the sync identity connection.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ForwardStateSenderInterface
{
    /**
     * Deliver the request to the primary, throwing when it could not be delivered or the primary rejected it.
     *
     * The caller leaves the subject pending and retries later.
     */
    public function send(ForwardPasswordPolicyStateRequest $request): void;
}
