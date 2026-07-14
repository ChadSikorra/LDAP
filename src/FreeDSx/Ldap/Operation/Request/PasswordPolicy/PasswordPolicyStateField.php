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

namespace FreeDSx\Ldap\Operation\Request\PasswordPolicy;

use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;

/**
 * The closed set of bind-originated password-policy state a read-only replica may forward to the primary.
 *
 * The enumeration is the allow-list: a value outside it is unrepresentable, so the forward op cannot carry any
 * non-password-policy modification.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum PasswordPolicyStateField: int
{
    case FailureTime = 0;

    case AccountLockedTime = 1;

    case LastSuccess = 2;

    case GraceUseTime = 3;

    public function attributeName(): string
    {
        return match ($this) {
            self::FailureTime => PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
            self::AccountLockedTime => PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
            self::LastSuccess => PasswordPolicyOid::NAME_PWD_LAST_SUCCESS,
            self::GraceUseTime => PasswordPolicyOid::NAME_PWD_GRACE_USE_TIME,
        };
    }
}
