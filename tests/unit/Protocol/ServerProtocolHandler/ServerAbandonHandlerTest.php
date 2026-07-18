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

use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerAbandonHandler;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerAbandonHandlerTest extends TestCase
{
    private TokenInterface&MockObject $mockToken;

    private ServerAbandonHandler $subject;

    protected function setUp(): void
    {
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->subject = new ServerAbandonHandler();
    }

    public function test_it_sends_no_response_per_rfc4511(): void
    {
        $stream = $this->subject->handleRequest(
            new LdapMessageRequest(
                2,
                new AbandonRequest(1),
            ),
            $this->mockToken,
        );

        $this->assertSame(
            [],
            [...$stream->messages],
        );
    }
}
