<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Server\Proxy;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcome;
use FreeDSx\Ldap\Server\Proxy\ProxyRequestForwarder;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ProxyRequestForwarderTest extends TestCase
{
    private LdapClient&MockObject $client;

    private ServerQueue&MockObject $queue;

    private TokenInterface&MockObject $token;

    private ProxyRequestForwarder $subject;

    protected function setUp(): void
    {
        $this->client = $this->createMock(LdapClient::class);
        $this->queue = $this->createMock(ServerQueue::class);
        $this->token = $this->createMock(TokenInterface::class);
        $this->subject = new ProxyRequestForwarder(
            $this->client,
            $this->queue,
        );
    }

    public function test_it_relays_a_single_response_under_the_original_message_id(): void
    {
        $this->client
            ->method('sendAndReceive')
            ->willReturn(new LdapMessageResponse(
                99,
                new DeleteResponse(ResultCode::SUCCESS),
            ));

        $this->queue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::callback(
                static fn(LdapMessageResponse $response): bool => $response->getMessageId() === 7,
            ));

        $result = $this->subject->handle($this->contextFor(
            7,
            new DeleteRequest('cn=foo,dc=bar'),
        ));

        self::assertSame(OperationOutcome::Succeeded, $result->outcome()->outcome());
    }

    public function test_it_relays_an_upstream_error_as_a_response(): void
    {
        $this->client
            ->method('sendAndReceive')
            ->willThrowException(new OperationException(
                'No such object',
                ResultCode::NO_SUCH_OBJECT,
            ));

        $this->queue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::callback(static function (LdapMessageResponse $response): bool {
                $result = $response->getResponse();

                return $result instanceof LdapResult
                    && $result->getResultCode() === ResultCode::NO_SUCH_OBJECT;
            }));

        $result = $this->subject->handle($this->contextFor(
            1,
            new DeleteRequest('cn=missing,dc=bar'),
        ));

        self::assertSame(OperationOutcome::Failed, $result->outcome()->outcome());
    }

    public function test_it_closes_both_connections_on_unbind(): void
    {
        $this->client
            ->expects(self::once())
            ->method('unbind');
        $this->queue
            ->expects(self::once())
            ->method('close');

        $this->subject->handle($this->contextFor(
            1,
            new UnbindRequest(),
        ));
    }

    public function test_it_does_not_forward_an_abandon(): void
    {
        $this->client
            ->expects(self::never())
            ->method('sendAndReceive');

        $result = $this->subject->handle($this->contextFor(
            1,
            new AbandonRequest(2),
        ));

        self::assertSame(OperationOutcome::Succeeded, $result->outcome()->outcome());
    }

    private function contextFor(
        int $messageId,
        RequestInterface $request,
    ): ServerRequestContext {
        return new ServerRequestContext(
            new LdapMessageRequest($messageId, $request),
            $this->token,
        );
    }
}
