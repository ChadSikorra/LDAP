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

namespace FreeDSx\Ldap\Server\Backend\Auth;

use FreeDSx\Ldap\Entry\Dn;

/**
 * Carries the resolved directory DN and stored password.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SaslIdentity
{
    public function __construct(
        public string $password,
        public Dn $resolvedDn,
    ) {}
}
