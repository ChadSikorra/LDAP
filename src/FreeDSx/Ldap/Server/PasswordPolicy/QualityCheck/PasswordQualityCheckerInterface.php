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

namespace FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck;

use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;
use SensitiveParameter;

/**
 * Pluggable check applied to a new password before it is hashed and written.
 */
interface PasswordQualityCheckerInterface
{
    /**
     * @return ?int A {@see \FreeDSx\Ldap\Control\PwdPolicyError} code on violation; null when acceptable.
     */
    public function check(
        #[SensitiveParameter]
        string $plain,
        PasswordQualityRules $rules,
    ): ?int;
}
