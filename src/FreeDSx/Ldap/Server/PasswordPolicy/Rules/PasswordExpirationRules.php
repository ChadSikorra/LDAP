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
 * Rules governing password expiration / any grace window (draft-behera-10 §5.2.3, §5.2.7-5.2.8, §5.2.16, §5.2.19).
 *
 * @api
 */
final readonly class PasswordExpirationRules
{
    /**
     * @param int<0, max>|null $maxAge
     * @param int<0, max>|null $expireWarning
     * @param int<0, max>|null $graceAuthnLimit
     * @param int<0, max>|null $graceExpiry
     * @param int<0, max>|null $maxIdle
     */
    public function __construct(
        public ?int $maxAge = null,
        public ?int $expireWarning = null,
        public ?int $graceAuthnLimit = null,
        public ?int $graceExpiry = null,
        public ?int $maxIdle = null,
    ) {}
}
