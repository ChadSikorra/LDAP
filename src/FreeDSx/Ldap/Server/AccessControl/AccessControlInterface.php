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

namespace FreeDSx\Ldap\Server\AccessControl;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Guards LDAP operations and read-side attribute visibility.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface AccessControlInterface
{
    /**
     * Assert that $token may perform $operation on $dn.
     *
     * @throws OperationException with ResultCode::INSUFFICIENT_ACCESS_RIGHTS on denial
     */
    public function authorizeOperation(
        OperationType $operation,
        TokenInterface $token,
        Dn $dn,
    ): void;

    /**
     * Assert that $token may access $attribute on $dn (gates Compare, Add, and Modify operations).
     *
     * @throws OperationException with ResultCode::INSUFFICIENT_ACCESS_RIGHTS on denial
     */
    public function authorizeAttribute(
        TokenInterface $token,
        Dn $dn,
        string $attribute,
    ): void;

    /**
     * Assert that the token may use the request control identified by the OID against the given DN.
     *
     * @throws OperationException with ResultCode::INSUFFICIENT_ACCESS_RIGHTS on denial
     */
    public function authorizeControl(
        TokenInterface $token,
        Dn $dn,
        string $controlOid,
    ): void;

    /**
     * Coarse, target-independent gate: whether $token could use the control against a target in general.
     *
     * Note: Only authenticated identities are considered.
     */
    public function mayUseControl(
        TokenInterface $token,
        string $controlOid,
    ): bool;

    /**
     * Return $entry with unreadable attributes removed, or null to suppress the entry entirely.
     */
    public function filterEntry(
        TokenInterface $token,
        Entry $entry,
    ): ?Entry;
}
