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

namespace FreeDSx\Ldap\Server\Token;

use FreeDSx\Ldap\Entry\Dn;

/**
 * Implemented by tokens that represent a successfully authenticated identity with a resolved DN.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface AuthenticatedTokenInterface extends TokenInterface
{
    public function getResolvedDn(): Dn;

    /**
     * Whether the bound identity must change its password before any other operation is permitted (pwdReset).
     */
    public function mustChangePassword(): bool;
}
