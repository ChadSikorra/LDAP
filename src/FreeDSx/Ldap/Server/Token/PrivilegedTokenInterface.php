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

/**
 * Marks a token whose identity bypasses access control and password-policy enforcement (the manager super-user).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PrivilegedTokenInterface extends TokenInterface {}
