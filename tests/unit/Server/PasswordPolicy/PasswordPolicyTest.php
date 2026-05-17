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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\PasswordPolicyException;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordLockoutRules;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;
use PHPUnit\Framework\TestCase;

final class PasswordPolicyTest extends TestCase
{
    public function test_defaults_apply_for_an_empty_policy(): void
    {
        $policy = new PasswordPolicy();

        self::assertSame(
            AttributeTypeOid::NAME_USER_PASSWORD,
            $policy->pwdAttribute,
        );
        self::assertNull($policy->quality->minLength);
        self::assertNull($policy->lockout->enabled);
        self::assertNull($policy->lockout->maxFailure);
        self::assertNull($policy->change->mustChange);
        self::assertNull($policy->expiration->maxAge);
    }

    public function test_named_args_construction_via_sub_dtos(): void
    {
        $policy = new PasswordPolicy(
            quality: new PasswordQualityRules(minLength: 8),
            lockout: new PasswordLockoutRules(
                enabled: true,
                duration: 300,
                maxFailure: 5,
            ),
        );

        self::assertSame(
            8,
            $policy->quality->minLength,
        );
        self::assertTrue($policy->lockout->enabled);
        self::assertSame(
            5,
            $policy->lockout->maxFailure,
        );
        self::assertSame(
            300,
            $policy->lockout->duration,
        );
    }

    public function test_from_entry_decodes_full_policy(): void
    {
        $entry = Entry::fromArray(
            'cn=default,ou=policies,dc=example,dc=com',
            [
                'pwdAttribute' => 'userPassword',
                'pwdMinAge' => '60',
                'pwdMaxAge' => '7776000',
                'pwdInHistory' => '5',
                'pwdCheckQuality' => '2',
                'pwdMinLength' => '8',
                'pwdMaxLength' => '128',
                'pwdExpireWarning' => '604800',
                'pwdGraceAuthNLimit' => '3',
                'pwdGraceExpiry' => '86400',
                'pwdLockout' => 'TRUE',
                'pwdLockoutDuration' => '900',
                'pwdMaxFailure' => '5',
                'pwdFailureCountInterval' => '300',
                'pwdMustChange' => 'TRUE',
                'pwdAllowUserChange' => 'TRUE',
                'pwdSafeModify' => 'FALSE',
                'pwdMinDelay' => '1',
                'pwdMaxDelay' => '60',
                'pwdMaxIdle' => '2592000',
            ],
        );

        $policy = PasswordPolicy::fromEntry($entry);

        self::assertSame(
            'userPassword',
            $policy->pwdAttribute,
        );

        self::assertSame(
            8,
            $policy->quality->minLength,
        );
        self::assertSame(
            128,
            $policy->quality->maxLength,
        );
        self::assertSame(
            5,
            $policy->quality->inHistory,
        );
        self::assertSame(
            2,
            $policy->quality->checkQuality,
        );

        self::assertSame(
            60,
            $policy->change->minAge,
        );
        self::assertTrue($policy->change->mustChange);
        self::assertTrue($policy->change->allowUserChange);
        self::assertFalse($policy->change->safeModify);

        self::assertSame(
            7776000,
            $policy->expiration->maxAge,
        );
        self::assertSame(
            604800,
            $policy->expiration->expireWarning,
        );
        self::assertSame(
            3,
            $policy->expiration->graceAuthnLimit,
        );
        self::assertSame(
            86400,
            $policy->expiration->graceExpiry,
        );
        self::assertSame(
            2592000,
            $policy->expiration->maxIdle,
        );

        self::assertTrue($policy->lockout->enabled);
        self::assertSame(
            900,
            $policy->lockout->duration,
        );
        self::assertSame(
            5,
            $policy->lockout->maxFailure,
        );
        self::assertSame(
            300,
            $policy->lockout->failureCountInterval,
        );
        self::assertSame(
            1,
            $policy->lockout->minDelay,
        );
        self::assertSame(
            60,
            $policy->lockout->maxDelay,
        );
    }

    public function test_from_entry_leaves_absent_fields_null(): void
    {
        $entry = Entry::fromArray(
            'cn=minimal,ou=policies,dc=example,dc=com',
            ['pwdAttribute' => 'userPassword'],
        );

        $policy = PasswordPolicy::fromEntry($entry);

        self::assertNull($policy->change->minAge);
        self::assertNull($policy->lockout->enabled);
        self::assertNull($policy->change->safeModify);
        self::assertNull($policy->quality->maxLength);
        self::assertNull($policy->expiration->maxIdle);
    }

    public function test_from_entry_accepts_lowercase_boolean(): void
    {
        $entry = Entry::fromArray(
            'cn=lower,ou=policies,dc=example,dc=com',
            [
                'pwdAttribute' => 'userPassword',
                'pwdLockout' => 'true',
            ],
        );

        $policy = PasswordPolicy::fromEntry($entry);

        self::assertTrue($policy->lockout->enabled);
    }

    public function test_default_sub_dtos_have_all_null_fields(): void
    {
        $policy = new PasswordPolicy();

        self::assertNull($policy->quality->maxLength);
        self::assertNull($policy->quality->inHistory);
        self::assertNull($policy->change->mustChange);
        self::assertNull($policy->change->safeModify);
        self::assertNull($policy->expiration->maxAge);
        self::assertNull($policy->expiration->graceAuthnLimit);
        self::assertNull($policy->lockout->duration);
        self::assertNull($policy->lockout->minDelay);
    }

    public function test_from_entry_rejects_missing_pwd_attribute(): void
    {
        $entry = Entry::fromArray(
            'cn=bad,ou=policies,dc=example,dc=com',
            ['pwdMinLength' => '8'],
        );

        $this->expectException(PasswordPolicyException::class);
        $this->expectExceptionMessage('missing the required pwdAttribute');

        PasswordPolicy::fromEntry($entry);
    }

    public function test_from_entry_rejects_non_integer_value(): void
    {
        $entry = Entry::fromArray(
            'cn=bad,ou=policies,dc=example,dc=com',
            [
                'pwdAttribute' => 'userPassword',
                'pwdMinLength' => 'eight',
            ],
        );

        $this->expectException(PasswordPolicyException::class);
        $this->expectExceptionMessage('expected a non-negative integer');

        PasswordPolicy::fromEntry($entry);
    }

    public function test_from_entry_rejects_negative_integer_value(): void
    {
        $entry = Entry::fromArray(
            'cn=bad,ou=policies,dc=example,dc=com',
            [
                'pwdAttribute' => 'userPassword',
                'pwdMaxAge' => '-1',
            ],
        );

        $this->expectException(PasswordPolicyException::class);
        $this->expectExceptionMessage('expected a non-negative integer');

        PasswordPolicy::fromEntry($entry);
    }

    public function test_from_entry_rejects_non_boolean_value(): void
    {
        $entry = Entry::fromArray(
            'cn=bad,ou=policies,dc=example,dc=com',
            [
                'pwdAttribute' => 'userPassword',
                'pwdLockout' => 'maybe',
            ],
        );

        $this->expectException(PasswordPolicyException::class);
        $this->expectExceptionMessage('non-boolean value');

        PasswordPolicy::fromEntry($entry);
    }
}
