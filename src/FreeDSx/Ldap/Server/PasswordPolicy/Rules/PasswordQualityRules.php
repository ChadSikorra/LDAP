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
 * Constraints on what a new password is allowed to contain (draft-behera-10 §5.2.4-5.2.6, §5.2.11).
 *
 * @api
 */
final readonly class PasswordQualityRules
{
    /**
     * @param int<0, max>|null $minLength
     * @param int<0, max>|null $maxLength
     * @param int<0, max>|null $inHistory
     * @param int<0, max>|null $checkQuality
     */
    public function __construct(
        public ?int $minLength = null,
        public ?int $maxLength = null,
        public ?int $inHistory = null,
        public ?int $checkQuality = null,
    ) {}
}
