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

namespace Tests\Unit\FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\DnBindNameResolver;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyTargetResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyComponentFactory;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Clock\SystemClock;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\ServerProtocolFactory;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Socket;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerProtocolFactoryTest extends TestCase
{
    private ServerProtocolFactory $subject;

    private HandlerFactoryInterface&MockObject $mockHandlerFactory;

    private ServerAuthorization&MockObject $mockServerAuthorization;

    protected function setUp(): void
    {
        $this->mockHandlerFactory = $this->createMock(HandlerFactoryInterface::class);
        $this->mockServerAuthorization = $this->createMock(ServerAuthorization::class);

        $this->mockHandlerFactory
            ->method('makeBackend')
            ->willReturn(new WritableStorageBackend(new InMemoryStorage()));

        $options = new ServerOptions();
        $writeDispatcher = new WriteOperationDispatcher();

        $this->subject = new ServerProtocolFactory(
            $this->mockHandlerFactory,
            $options,
            $this->mockServerAuthorization,
            $this->passwordPolicyEngine(),
            new ServerProtocolHandlerFactory($options),
            new PasswordModifyTargetResolver(
                $this->mockHandlerFactory->makeBackend(),
                new DnBindNameResolver(),
            ),
            new PasswordHashService(),
            $writeDispatcher,
            new PasswordPolicyComponentFactory(
                $this->mockHandlerFactory,
                $options,
                $writeDispatcher,
                $this->passwordPolicyEngine(),
            ),
        );
    }

    private function passwordPolicyEngine(): PasswordPolicyEngine
    {
        return new PasswordPolicyEngine(
            new SystemClock(),
            new PasswordChangeConstraintChain([]),
        );
    }

    public function test_it_should_make_a_ServerProtocolInstance(): void
    {
        $mockSocket = $this->createMock(Socket::class);

        $this->mockHandlerFactory
            ->expects($this->once())
            ->method('makeBackend')
            ->willReturn(new WritableStorageBackend(new InMemoryStorage()));

        $this->subject->make($mockSocket);
    }

    public function test_it_includes_sasl_when_mechanisms_are_configured(): void
    {
        $this->expectNotToPerformAssertions();

        $mockSocket = $this->createMock(Socket::class);

        $options = (new ServerOptions())->setSaslMechanisms(ServerOptions::SASL_PLAIN);
        $writeDispatcher = new WriteOperationDispatcher();
        $subject = new ServerProtocolFactory(
            $this->mockHandlerFactory,
            $options,
            $this->mockServerAuthorization,
            $this->passwordPolicyEngine(),
            new ServerProtocolHandlerFactory($options),
            new PasswordModifyTargetResolver(
                $this->mockHandlerFactory->makeBackend(),
                new DnBindNameResolver(),
            ),
            new PasswordHashService(),
            $writeDispatcher,
            new PasswordPolicyComponentFactory(
                $this->mockHandlerFactory,
                $options,
                $writeDispatcher,
                $this->passwordPolicyEngine(),
            ),
        );

        $subject->make($mockSocket);
    }

    public function test_it_wraps_the_authenticator_when_password_policy_is_enabled(): void
    {
        $this->expectNotToPerformAssertions();

        $mockSocket = $this->createMock(Socket::class);

        $this->mockHandlerFactory
            ->method('makePasswordAuthenticator')
            ->willReturn($this->createMock(PasswordAuthenticatableInterface::class));
        $this->mockHandlerFactory
            ->method('makeIdentityResolverChain')
            ->willReturn($this->createMock(BindNameResolverInterface::class));
        $this->mockHandlerFactory
            ->method('makeWriteDispatcher')
            ->willReturn(new WriteOperationDispatcher());

        $options = (new ServerOptions())->setPasswordPolicy(new PasswordPolicy());
        $writeDispatcher = new WriteOperationDispatcher();
        $subject = new ServerProtocolFactory(
            $this->mockHandlerFactory,
            $options,
            $this->mockServerAuthorization,
            $this->passwordPolicyEngine(),
            new ServerProtocolHandlerFactory($options),
            new PasswordModifyTargetResolver(
                $this->mockHandlerFactory->makeBackend(),
                new DnBindNameResolver(),
            ),
            new PasswordHashService(),
            $writeDispatcher,
            new PasswordPolicyComponentFactory(
                $this->mockHandlerFactory,
                $options,
                $writeDispatcher,
                $this->passwordPolicyEngine(),
            ),
        );

        $subject->make($mockSocket);
    }
}
