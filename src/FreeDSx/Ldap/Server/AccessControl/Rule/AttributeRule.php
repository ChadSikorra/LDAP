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
 * An ordered access control rule evaluated by filterEntry() per attribute.
 *
 * An empty $attributes list matches all attributes. Attribute names are stored lowercase.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class AttributeRule
{
    /**
     * @param string[] $attributes Lowercase attribute names. Empty matches all attributes.
     */
    public function __construct(
        public Effect $effect,
        public SubjectMatcherInterface $subject,
        public TargetMatcherInterface $target,
        public array $attributes,
    ) {}

    public static function allow(
        SubjectMatcherInterface $subject,
        TargetMatcherInterface $target = new AnyTargetMatcher(),
        string ...$attributes,
    ): self {
        return new self(
            Effect::Allow,
            $subject,
            $target,
            array_map('strtolower', $attributes),
        );
    }

    public static function deny(
        SubjectMatcherInterface $subject,
        TargetMatcherInterface $target = new AnyTargetMatcher(),
        string ...$attributes,
    ): self {
        return new self(
            Effect::Deny,
            $subject,
            $target,
            array_map('strtolower', $attributes),
        );
    }
}
