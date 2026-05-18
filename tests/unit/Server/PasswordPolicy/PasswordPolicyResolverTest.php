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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Backend\RecordingLdapBackend;

final class PasswordPolicyResolverTest extends TestCase
{
    private const USER_DN = 'uid=alice,dc=example,dc=com';
    private const SUBENTRY_DN = 'cn=subentry-policy,ou=policies,dc=example,dc=com';
    private const DEFAULT_DN = 'cn=default,ou=policies,dc=example,dc=com';

    public function test_returns_null_when_no_source_configured(): void
    {
        $resolver = new PasswordPolicyResolver(
            new RecordingLdapBackend(),
            defaultPolicyDn: null,
            inMemoryFallback: null,
        );

        self::assertNull($resolver->resolveFor($this->userEntry()));
    }

    public function test_falls_back_to_in_memory_policy_when_no_dn_configured(): void
    {
        $fallback = new PasswordPolicy(quality: new PasswordQualityRules(minLength: 8));

        $resolver = new PasswordPolicyResolver(
            new RecordingLdapBackend(),
            defaultPolicyDn: null,
            inMemoryFallback: $fallback,
        );

        self::assertSame(
            $fallback,
            $resolver->resolveFor($this->userEntry()),
        );
    }

    public function test_resolves_from_default_dn_when_user_has_no_subentry(): void
    {
        $defaultEntry = $this->policyEntry(
            self::DEFAULT_DN,
            ['pwdMinLength' => '10'],
        );
        $backend = new RecordingLdapBackend([self::DEFAULT_DN => $defaultEntry]);

        $resolver = new PasswordPolicyResolver(
            $backend,
            defaultPolicyDn: new Dn(self::DEFAULT_DN),
            inMemoryFallback: null,
        );

        $resolved = $resolver->resolveFor($this->userEntry());

        self::assertNotNull($resolved);
        self::assertSame(
            10,
            $resolved->quality->minLength,
        );
    }

    public function test_resolves_from_user_subentry_when_present(): void
    {
        $subentryEntry = $this->policyEntry(
            self::SUBENTRY_DN,
            ['pwdMinLength' => '12'],
        );
        $defaultEntry = $this->policyEntry(
            self::DEFAULT_DN,
            ['pwdMinLength' => '6'],
        );
        $backend = new RecordingLdapBackend([
            self::SUBENTRY_DN => $subentryEntry,
            self::DEFAULT_DN => $defaultEntry,
        ]);

        $resolver = new PasswordPolicyResolver(
            $backend,
            defaultPolicyDn: new Dn(self::DEFAULT_DN),
            inMemoryFallback: null,
        );

        $resolved = $resolver->resolveFor(
            $this->userEntry(['pwdPolicySubentry' => self::SUBENTRY_DN]),
        );

        self::assertNotNull($resolved);
        self::assertSame(
            12,
            $resolved->quality->minLength,
        );
    }

    public function test_missing_subentry_dn_falls_through_to_default(): void
    {
        $defaultEntry = $this->policyEntry(
            self::DEFAULT_DN,
            ['pwdMinLength' => '6'],
        );
        $backend = new RecordingLdapBackend([
            self::DEFAULT_DN => $defaultEntry,
        ]);

        $resolver = new PasswordPolicyResolver(
            $backend,
            defaultPolicyDn: new Dn(self::DEFAULT_DN),
            inMemoryFallback: null,
        );

        $resolved = $resolver->resolveFor(
            $this->userEntry(['pwdPolicySubentry' => 'cn=missing,ou=policies,dc=example,dc=com']),
        );

        self::assertNotNull($resolved);
        self::assertSame(
            6,
            $resolved->quality->minLength,
        );
    }

    public function test_repeated_lookups_hit_the_cache(): void
    {
        $defaultEntry = $this->policyEntry(
            self::DEFAULT_DN,
            ['pwdMinLength' => '6'],
        );
        $backend = new RecordingLdapBackend([self::DEFAULT_DN => $defaultEntry]);

        $resolver = new PasswordPolicyResolver(
            $backend,
            defaultPolicyDn: new Dn(self::DEFAULT_DN),
            inMemoryFallback: null,
        );

        $resolver->resolveFor($this->userEntry());
        $resolver->resolveFor($this->userEntry());
        $resolver->resolveFor($this->userEntry());

        self::assertSame(
            1,
            $backend->getCallCount(self::DEFAULT_DN),
        );
    }

    /**
     * @param array<string, string> $extra
     */
    private function userEntry(array $extra = []): Entry
    {
        return Entry::fromArray(
            self::USER_DN,
            ['uid' => 'alice'] + $extra,
        );
    }

    /**
     * @param array<string, string> $extra
     */
    private function policyEntry(
        string $dn,
        array $extra,
    ): Entry {
        return Entry::fromArray(
            $dn,
            ['pwdAttribute' => 'userPassword'] + $extra,
        );
    }
}
