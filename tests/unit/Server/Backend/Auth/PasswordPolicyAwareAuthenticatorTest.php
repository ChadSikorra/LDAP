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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Auth;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordPolicyAwareAuthenticator;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\SystemChangeWriter;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyBindGuard;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordLockoutRules;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Backend\RecordingWriteHandler;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;

final class PasswordPolicyAwareAuthenticatorTest extends TestCase
{
    private const DN = 'cn=foo,dc=example,dc=com';

    private PasswordAuthenticatableInterface&MockObject $inner;
    private BindNameResolverInterface&MockObject $nameResolver;
    private RecordingWriteHandler $writeHandler;
    private PasswordPolicyContext $context;

    protected function setUp(): void
    {
        $this->inner = $this->createMock(PasswordAuthenticatableInterface::class);
        $this->nameResolver = $this->createMock(BindNameResolverInterface::class);
        $this->writeHandler = new RecordingWriteHandler();
        $this->context = new PasswordPolicyContext();
    }

    public function test_delegates_when_no_entry_is_found(): void
    {
        $this->nameResolver
            ->method('resolve')
            ->willReturn(null);
        $token = $this->expectInnerReturnsToken();

        $result = $this->authenticator(new PasswordPolicy())->authenticate(
            'foo',
            'secret',
        );

        self::assertSame(
            $token,
            $result,
        );
        self::assertNull($this->context->getOutcome());
    }

    public function test_delegates_when_no_policy_applies(): void
    {
        $this->nameResolver
            ->method('resolve')
            ->willReturn($this->entry());
        $token = $this->expectInnerReturnsToken();

        $result = $this->authenticator(null)->authenticate(
            'foo',
            'secret',
        );

        self::assertSame(
            $token,
            $result,
        );
        self::assertNull($this->context->getOutcome());
    }

    public function test_locked_account_is_denied_before_inner_runs(): void
    {
        $this->nameResolver
            ->method('resolve')
            ->willReturn($this->entry([
                PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME => PasswordPolicyOid::PERMANENT_LOCK_SENTINEL,
            ]));
        $this->inner
            ->expects(self::never())
            ->method('authenticate');

        $this->expectException(OperationException::class);

        $this->authenticator(new PasswordPolicy())->authenticate(
            'foo',
            'secret',
        );
    }

    public function test_successful_bind_records_outcome(): void
    {
        $this->nameResolver
            ->method('resolve')
            ->willReturn($this->entry());
        $token = $this->expectInnerReturnsToken();

        $result = $this->authenticator(new PasswordPolicy())->authenticate(
            'foo',
            'secret',
        );

        self::assertSame(
            $token,
            $result,
        );
        self::assertFalse($this->context->getOutcome()?->denied);
    }

    public function test_invalid_credentials_records_a_failure(): void
    {
        $this->nameResolver
            ->method('resolve')
            ->willReturn($this->entry());
        $this->inner
            ->method('authenticate')
            ->willThrowException(new OperationException(
                'Invalid credentials.',
                ResultCode::INVALID_CREDENTIALS,
            ));

        try {
            $this->authenticator($this->lockoutPolicy())->authenticate(
                'foo',
                'secret',
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INVALID_CREDENTIALS,
                $e->getCode(),
            );
        }

        self::assertCount(
            1,
            $this->writeHandler->dispatched,
        );
    }

    public function test_non_credential_failure_is_not_recorded(): void
    {
        $this->nameResolver
            ->method('resolve')
            ->willReturn($this->entry());
        $this->inner
            ->method('authenticate')
            ->willThrowException(new OperationException(
                'Server is busy.',
                ResultCode::BUSY,
            ));

        try {
            $this->authenticator($this->lockoutPolicy())->authenticate(
                'foo',
                'secret',
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::BUSY,
                $e->getCode(),
            );
        }

        self::assertSame(
            [],
            $this->writeHandler->dispatched,
        );
    }

    private function authenticator(?PasswordPolicy $policy): PasswordPolicyAwareAuthenticator
    {
        $backend = $this->createMock(LdapBackendInterface::class);
        $engine = new PasswordPolicyEngine(
            clock: FrozenClock::fromString('2026-05-20T12:00:00Z'),
            changeConstraints: new PasswordChangeConstraintChain([]),
        );
        $guard = new PasswordPolicyBindGuard(
            $engine,
            new SystemChangeWriter(new WriteOperationDispatcher($this->writeHandler)),
            $this->context,
            new EventLogger(null),
        );

        return new PasswordPolicyAwareAuthenticator(
            $this->inner,
            $this->nameResolver,
            $backend,
            new PasswordPolicyResolver(
                $backend,
                null,
                $policy,
            ),
            $guard,
        );
    }

    private function expectInnerReturnsToken(): BindToken
    {
        $token = BindToken::fromDn(
            self::DN,
            'secret',
        );
        $this->inner
            ->method('authenticate')
            ->willReturn($token);

        return $token;
    }

    /**
     * @param array<string, string> $attributes
     */
    private function entry(array $attributes = []): Entry
    {
        return Entry::fromArray(
            new Dn(self::DN),
            $attributes,
        );
    }

    private function lockoutPolicy(): PasswordPolicy
    {
        return new PasswordPolicy(
            lockout: new PasswordLockoutRules(
                enabled: true,
                maxFailure: 3,
            ),
        );
    }
}
