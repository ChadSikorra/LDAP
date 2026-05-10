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

namespace Tests\Unit\FreeDSx\Ldap\Server\AccessControl\Rule;

use FreeDSx\Ldap\Server\AccessControl\OperationType;
use FreeDSx\Ldap\Server\AccessControl\Rule\Effect;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\AnySubjectMatcher;
use FreeDSx\Ldap\Server\AccessControl\Target\AnyTargetMatcher;
use PHPUnit\Framework\TestCase;

final class OperationRuleTest extends TestCase
{
    public function test_allow_sets_effect_to_allow(): void
    {
        $rule = OperationRule::allow(new AnySubjectMatcher());

        self::assertSame(
            Effect::Allow,
            $rule->effect,
        );
    }

    public function test_deny_sets_effect_to_deny(): void
    {
        $rule = OperationRule::deny(new AnySubjectMatcher());

        self::assertSame(
            Effect::Deny,
            $rule->effect,
        );
    }

    public function test_empty_operations_list_when_none_specified(): void
    {
        $rule = OperationRule::allow(new AnySubjectMatcher());

        self::assertSame(
            [],
            $rule->operations,
        );
    }

    public function test_operations_are_stored_when_provided(): void
    {
        $rule = OperationRule::allow(
            new AnySubjectMatcher(),
            new AnyTargetMatcher(),
            OperationType::Search,
            OperationType::Compare,
        );

        self::assertSame(
            [OperationType::Search, OperationType::Compare],
            $rule->operations,
        );
    }

    public function test_default_target_is_any_target_matcher(): void
    {
        $rule = OperationRule::allow(new AnySubjectMatcher());

        self::assertInstanceOf(
            AnyTargetMatcher::class,
            $rule->target,
        );
    }
}
