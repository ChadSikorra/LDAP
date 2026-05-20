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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Constraint;

use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use SensitiveParameter;

/**
 * Snapshot of the inputs to a single password-change evaluation, passed to each {@see PasswordChangeConstraint}.
 */
final readonly class PasswordChangeAttempt
{
    public function __construct(
        #[SensitiveParameter]
        public string $newPassword,
        #[SensitiveParameter]
        public ?string $oldPassword,
        public UserPasswordState $state,
        public PasswordPolicy $policy,
        public bool $isSelf,
    ) {}
}
