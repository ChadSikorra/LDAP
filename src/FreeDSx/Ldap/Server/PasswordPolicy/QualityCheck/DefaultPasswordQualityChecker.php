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

use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Schema\Text;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;
use SensitiveParameter;

/**
 * Default checker enforcing pwdMinLength and pwdMaxLength. Operators wanting composition / strength
 * rules should plug their own {@see PasswordQualityCheckerInterface} via {@see \FreeDSx\Ldap\ServerOptions}.
 */
final class DefaultPasswordQualityChecker implements PasswordQualityCheckerInterface
{
    public function check(
        #[SensitiveParameter]
        string $plain,
        PasswordQualityRules $rules,
    ): ?int {
        if ($rules->checkQuality === 0) {
            return null;
        }

        $length = Text::lengthOf($plain);

        if ($rules->minLength !== null && $length < $rules->minLength) {
            return PwdPolicyError::PASSWORD_TOO_SHORT;
        }
        if ($rules->maxLength !== null && $length > $rules->maxLength) {
            return PwdPolicyError::INSUFFICIENT_PASSWORD_QUALITY;
        }

        return null;
    }
}
