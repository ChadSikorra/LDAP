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
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;

/**
 * Implemented by tokens that represent a successfully authenticated identity with a resolved DN.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface AuthenticatedTokenInterface extends TokenInterface
{
    public function getResolvedDn(): Dn;

    /**
     * The bound identity as an authorization identity: the resolved DN, or the username when it is not a DN.
     */
    public function getAuthzId(): AuthzId;

    /**
     * Whether the bound identity must change its password before any other operation is permitted (pwdReset).
     */
    public function mustChangePassword(): bool;

    /**
     * Flags that the bound identity must change its password before any other operation is permitted.
     */
    public function markMustChangePassword(): void;

    /**
     * Lifts the restriction once the bound identity has changed its password within the session.
     */
    public function clearMustChangePassword(): void;
}
