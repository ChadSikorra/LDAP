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

namespace FreeDSx\Ldap\Server\PasswordModify;

use FreeDSx\Ldap\Entry\Dn;

/**
 * Outcome of a successful password modification: the target entry and any server-generated password.
 */
final readonly class PasswordModifyResult
{
    public function __construct(
        public Dn $targetDn,
        public ?string $generatedPassword,
    ) {}
}
