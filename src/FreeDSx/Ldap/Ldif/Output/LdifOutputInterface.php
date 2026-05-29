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

namespace FreeDSx\Ldap\Ldif\Output;

/**
 * Destination for streamed LDIF chunks produced by {@see \FreeDSx\Ldap\LdapServer::dump()}.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface LdifOutputInterface
{
    /**
     * @param iterable<string> $chunks
     */
    public function write(iterable $chunks): void;
}
