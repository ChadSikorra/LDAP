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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck;

use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\DefaultPasswordQualityChecker;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DefaultPasswordQualityCheckerTest extends TestCase
{
    private DefaultPasswordQualityChecker $subject;

    protected function setUp(): void
    {
        $this->subject = new DefaultPasswordQualityChecker();
    }

    public function test_unconstrained_rules_accept_any_value(): void
    {
        self::assertNull(
            $this->subject->check(
                'whatever',
                new PasswordQualityRules(),
            ),
        );
    }

    /**
     * @return array<string, array{0: string, 1: PasswordQualityRules, 2: ?int}>
     */
    public static function checkProvider(): array
    {
        return [
            'min length pass' => [
                'longenough',
                new PasswordQualityRules(minLength: 8),
                null,
            ],
            'min length exact boundary' => [
                'eightchr',
                new PasswordQualityRules(minLength: 8),
                null,
            ],
            'min length fail' => [
                'short',
                new PasswordQualityRules(minLength: 8),
                PwdPolicyError::PASSWORD_TOO_SHORT,
            ],
            'max length pass' => [
                'fits',
                new PasswordQualityRules(maxLength: 10),
                null,
            ],
            'max length exact boundary' => [
                'tencharsok',
                new PasswordQualityRules(maxLength: 10),
                null,
            ],
            'max length fail' => [
                'thispasswordistoolong',
                new PasswordQualityRules(maxLength: 10),
                PwdPolicyError::INSUFFICIENT_PASSWORD_QUALITY,
            ],
            'both bounds satisfied' => [
                'fitsperfectly',
                new PasswordQualityRules(minLength: 8, maxLength: 20),
                null,
            ],
            'min checked before max' => [
                'short',
                new PasswordQualityRules(minLength: 8, maxLength: 3),
                PwdPolicyError::PASSWORD_TOO_SHORT,
            ],
        ];
    }

    #[DataProvider('checkProvider')]
    public function test_check_maps_each_rule_violation(
        string $plain,
        PasswordQualityRules $rules,
        ?int $expected,
    ): void {
        self::assertSame(
            $expected,
            $this->subject->check(
                $plain,
                $rules,
            ),
        );
    }

    public function test_check_quality_zero_disables_all_checks(): void
    {
        self::assertNull(
            $this->subject->check(
                'short',
                new PasswordQualityRules(
                    minLength: 8,
                    checkQuality: 0,
                ),
            ),
            'pwdCheckQuality=0 must disable length enforcement entirely.',
        );
    }

    public function test_check_quality_enabled_still_enforces_length(): void
    {
        self::assertSame(
            PwdPolicyError::PASSWORD_TOO_SHORT,
            $this->subject->check(
                'short',
                new PasswordQualityRules(
                    minLength: 8,
                    checkQuality: 1,
                ),
            ),
        );
    }

    public function test_check_uses_multibyte_length_not_byte_length(): void
    {
        // 4 multi-byte chars; 12 bytes in UTF-8.
        $rules = new PasswordQualityRules(minLength: 8);

        self::assertSame(
            PwdPolicyError::PASSWORD_TOO_SHORT,
            $this->subject->check(
                '日本語版',
                $rules,
            ),
        );
    }
}
