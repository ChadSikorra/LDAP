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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerUnsupportedExtendedHandler;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerUnsupportedExtendedHandlerTest extends TestCase
{
    private ServerUnsupportedExtendedHandler $subject;

    private ServerQueue&MockObject $mockQueue;

    private TokenInterface&MockObject $mockToken;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->subject = new ServerUnsupportedExtendedHandler($this->mockQueue);
    }

    public function test_it_returns_protocol_error_with_response_name_echoing_the_request(): void
    {
        $oid = '1.2.3.4.5.6.7.8.9';
        $request = new LdapMessageRequest(
            42,
            new ExtendedRequest($oid),
        );

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::equalTo(new LdapMessageResponse(
                42,
                new ExtendedResponse(
                    new LdapResult(
                        ResultCode::PROTOCOL_ERROR,
                        '',
                        sprintf('The extended operation "%s" is not supported.', $oid),
                    ),
                    $oid,
                ),
            )));

        $this->subject->handleRequest(
            $request,
            $this->mockToken,
        );
    }

    public function test_it_rejects_critical_unsupported_controls_before_replying(): void
    {
        $request = new LdapMessageRequest(
            1,
            new ExtendedRequest('1.2.3.4.5'),
            new Control('1.2.3.4', true),
        );

        $this->mockQueue
            ->expects(self::never())
            ->method('sendMessage');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNAVAILABLE_CRITICAL_EXTENSION);

        $this->subject->handleRequest(
            $request,
            $this->mockToken,
        );
    }

    public function test_it_ignores_non_critical_unsupported_controls(): void
    {
        $request = new LdapMessageRequest(
            7,
            new ExtendedRequest('1.2.3.4.5'),
            new Control('1.2.3.4', false),
        );

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage');

        $this->subject->handleRequest(
            $request,
            $this->mockToken,
        );
    }
}
