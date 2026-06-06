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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Rules;

/**
 * Constraints on when and by whom a password may be changed (draft-behera-10 §5.2.2, §5.2.12-5.2.15).
 *
 * @api
 */
final readonly class PasswordChangeRules
{
    /**
     * @param int<0, max>|null $minAge
     */
    public function __construct(
        public ?int $minAge = null,
        public ?bool $mustChange = null,
        public ?bool $allowUserChange = null,
        public ?bool $safeModify = null,
    ) {}
}
