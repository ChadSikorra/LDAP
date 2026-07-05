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

namespace Tests\Unit\FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Response\AddResponse;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\ModifyDnResponse;
use FreeDSx\Ldap\Operation\Response\ModifyResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\ReplicaConfig;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Middleware\ReadOnlyMiddleware;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ReadOnlyMiddlewareTest extends TestCase
{
    private ServerQueue&MockObject $queue;

    private MiddlewareHandlerInterface&MockObject $next;

    private ReplicaConfig $replicaConfig;

    private ReadOnlyMiddleware $subject;

    protected function setUp(): void
    {
        $this->queue = $this->createMock(ServerQueue::class);
        $this->next = $this->createMock(MiddlewareHandlerInterface::class);
        $this->replicaConfig = new ReplicaConfig(
            (new ClientOptions())
                ->setServers(['primary.example.com'])
                ->setPort(389),
        );
        $this->subject = new ReadOnlyMiddleware(
            $this->queue,
            $this->replicaConfig,
        );
    }

    /**
     * @return array<string, array{RequestInterface, class-string<LdapResult>}>
     */
    public static function writeRequestProvider(): array
    {
        return [
            'add' => [
                Operations::add(new Entry('cn=foo,dc=example,dc=com')),
                AddResponse::class,
            ],
            'modify' => [
                Operations::modify('cn=foo,dc=example,dc=com'),
                ModifyResponse::class,
            ],
            'delete' => [
                Operations::delete('cn=foo,dc=example,dc=com'),
                DeleteResponse::class,
            ],
            'modifyDn' => [
                Operations::move('cn=foo,dc=example,dc=com', 'ou=new,dc=example,dc=com'),
                ModifyDnResponse::class,
            ],
            'passwordModify' => [
                Operations::passwordModify('cn=foo,dc=example,dc=com', 'old', 'new'),
                ExtendedResponse::class,
            ],
        ];
    }

    /**
     * @param class-string<LdapResult> $expectedResponse
     */
    #[DataProvider('writeRequestProvider')]
    public function test_a_write_is_referred_to_the_primary_by_default(
        RequestInterface $request,
        string $expectedResponse,
    ): void {
        $this->next
            ->expects(self::never())
            ->method('handle');

        $sent = null;
        $this->queue
            ->expects(self::once())
            ->method('sendMessage')
            ->willReturnCallback(function (LdapMessageResponse $message) use (&$sent): ServerQueue {
                $sent = $message;

                return $this->queue;
            });

        $result = $this->subject->process(
            $this->context($request),
            $this->next,
        );

        self::assertSame(
            ResultCode::REFERRAL,
            $result->resultCode(),
        );
        self::assertInstanceOf(
            LdapMessageResponse::class,
            $sent,
        );

        $response = $sent->getResponse();
        self::assertInstanceOf(
            $expectedResponse,
            $response,
        );
        self::assertSame(
            ResultCode::REFERRAL,
            $response->getResultCode(),
        );
        self::assertCount(
            1,
            $response->getReferrals(),
        );
    }

    public function test_a_write_is_rejected_when_referral_is_disabled(): void
    {
        $this->replicaConfig->setReferWrites(false);
        $this->next
            ->expects(self::never())
            ->method('handle');
        $this->queue
            ->expects(self::never())
            ->method('sendMessage');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->subject->process(
            $this->context(Operations::delete('cn=foo,dc=example,dc=com')),
            $this->next,
        );
    }

    public function test_a_read_passes_through_to_the_next_handler(): void
    {
        $context = $this->context(Operations::search(Filters::present('objectClass')));
        $expected = OperationOutcomeResult::succeeded();

        $this->next
            ->expects(self::once())
            ->method('handle')
            ->with($context)
            ->willReturn($expected);
        $this->queue
            ->expects(self::never())
            ->method('sendMessage');

        self::assertSame(
            $expected,
            $this->subject->process($context, $this->next),
        );
    }

    private function context(RequestInterface $request): ServerRequestContext
    {
        return new ServerRequestContext(new LdapMessageRequest(
            1,
            $request,
        ));
    }
}
