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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ConnectionControl;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerUnbindHandler;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\TestCase;

final class ServerUnbindHandlerTest extends TestCase
{
    private ServerUnbindHandler $subject;

    protected function setUp(): void
    {
        $this->subject = new ServerUnbindHandler();
    }

    public function test_it_should_handle_an_unbind_request(): void
    {
        $stream = $this->subject->handleRequest(
            new LdapMessageRequest(1, new UnbindRequest()),
            $this->createMock(TokenInterface::class),
        );

        $this->assertSame(
            [],
            [...$stream->messages],
        );
        $this->assertNotNull($stream->onComplete);
    }

    public function test_it_should_close_the_connection_on_completion(): void
    {
        $stream = $this->subject->handleRequest(
            new LdapMessageRequest(1, new UnbindRequest()),
            $this->createMock(TokenInterface::class),
        );

        $connection = $this->createMock(ConnectionControl::class);
        $connection
            ->expects($this->once())
            ->method('close');

        $this->assertNotNull($stream->onComplete);
        ($stream->onComplete)($connection);
    }
}
