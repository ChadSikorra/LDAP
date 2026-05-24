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

namespace FreeDSx\Ldap\Server\AccessControl\Rule;

use FreeDSx\Ldap\Server\AccessControl\Subject\SubjectMatcherInterface;
use FreeDSx\Ldap\Server\AccessControl\Target\AnyTargetMatcher;
use FreeDSx\Ldap\Server\AccessControl\Target\TargetMatcherInterface;

/**
 * An ordered access control rule gating use of a request control by OID.
 *
 * An empty $controlOids list matches all controls.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ControlRule
{
    /**
     * @param string[] $controlOids Control type OIDs. Empty matches all controls.
     */
    public function __construct(
        public Effect $effect,
        public SubjectMatcherInterface $subject,
        public TargetMatcherInterface $target,
        public array $controlOids,
    ) {}

    public static function allow(
        SubjectMatcherInterface $subject,
        TargetMatcherInterface $target = new AnyTargetMatcher(),
        string ...$controlOids,
    ): self {
        return new self(
            Effect::Allow,
            $subject,
            $target,
            $controlOids,
        );
    }

    public static function deny(
        SubjectMatcherInterface $subject,
        TargetMatcherInterface $target = new AnyTargetMatcher(),
        string ...$controlOids,
    ): self {
        return new self(
            Effect::Deny,
            $subject,
            $target,
            $controlOids,
        );
    }
}
