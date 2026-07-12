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
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Default access control: deny all anonymous operations, allow all authenticated operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SimpleAccessControl implements AccessControlInterface
{
    /**
     * @throws OperationException
     */
    public function authorizeOperation(
        OperationType $operation,
        TokenInterface $token,
        Dn $dn,
    ): void {
        if ($token instanceof AnonToken) {
            throw new OperationException(
                'Access denied.',
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            );
        }
    }

    public function authorizeAttribute(
        TokenInterface $token,
        Dn $dn,
        string $attribute,
        AttributeAccess $access,
    ): void {}

    /**
     * Privileged controls require an explicit grant the simple policy cannot express, so deny.
     *
     * @throws OperationException
     */
    public function authorizeControl(
        TokenInterface $token,
        Dn $dn,
        string $controlOid,
    ): void {
        throw new OperationException(
            'Access denied.',
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
        );
    }

    /**
     * Privileged extended operations require an explicit grant the simple policy cannot express, so deny.
     *
     * @throws OperationException
     */
    public function authorizeExtendedOperation(
        TokenInterface $token,
        string $oid,
    ): void {
        throw new OperationException(
            'Access denied.',
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
        );
    }

    /**
     * The simple policy cannot grant any control, so none is ever usable.
     */
    public function mayUseControl(
        TokenInterface $token,
        string $controlOid,
    ): bool {
        return false;
    }

    public function filterEntry(
        TokenInterface $token,
        Entry $entry,
    ): Entry {
        return $entry;
    }
}
