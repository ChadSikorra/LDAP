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

use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\ConnectionHandlerBuilderInterface;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\ServerProtocolFactory;
use FreeDSx\Socket\Socket;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerProtocolFactoryTest extends TestCase
{
    private ConnectionHandlerBuilderInterface&MockObject $builder;

    private ServerProtocolFactory $subject;

    protected function setUp(): void
    {
        $this->builder = $this->createMock(ConnectionHandlerBuilderInterface::class);
        $this->subject = new ServerProtocolFactory($this->builder);
    }

    public function test_it_delegates_make_to_the_connection_handler_builder(): void
    {
        $socket = $this->createMock(Socket::class);
        $context = new ConnectionContext();
        $handler = $this->createMock(ServerProtocolHandler::class);

        $this->builder
            ->expects($this->once())
            ->method('build')
            ->with(
                $socket,
                $context,
            )
            ->willReturn($handler);

        self::assertSame(
            $handler,
            $this->subject->make(
                $socket,
                $context,
            ),
        );
    }
}
