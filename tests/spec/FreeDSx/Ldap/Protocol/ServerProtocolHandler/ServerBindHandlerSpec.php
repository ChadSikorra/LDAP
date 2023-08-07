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

namespace spec\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerBindHandler;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ServerBindHandlerSpec extends ObjectBehavior
{
    public function let(ServerQueue $queue): void
    {
        $this->beConstructedWith($queue);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(ServerBindHandler::class);
    }

    public function it_should_return_a_token_on_success(ServerQueue $queue, RequestHandlerInterface $dispatcher): void
    {
        $bind = new LdapMessageRequest(1, new SimpleBindRequest('foo@bar', 'bar'));

        $dispatcher->bind('foo@bar', 'bar')
            ->shouldBeCalled()
            ->willReturn(true);
        $queue->sendMessage(new LdapMessageResponse(1, new BindResponse(
            new LdapResult(0)
        )))->shouldBeCalled()->willReturn($queue);

        $this->handleBind($bind, $dispatcher, $queue)->shouldBeLike(
            new BindToken('foo@bar', 'bar')
        );
    }

    public function it_should_throw_an_operations_exception_with_invalid_credentials_if_they_are_wrong(ServerQueue $queue, RequestHandlerInterface $dispatcher): void
    {
        $bind = new LdapMessageRequest(1, new SimpleBindRequest('foo@bar', 'bar'));

        $dispatcher->bind('foo@bar', 'bar')
            ->shouldBeCalled()
            ->willReturn(false);
        $queue->sendMessage(Argument::any())->shouldNotBeCalled();

        $this->shouldThrow(new OperationException('Invalid credentials.', ResultCode::INVALID_CREDENTIALS))
            ->during(
                'handleBind',
                [$bind, $dispatcher, $queue]
            );
    }

    public function it_should_validate_the_version(ServerQueue $queue, RequestHandlerInterface $dispatcher): void
    {
        $bind = new LdapMessageRequest(1, new SimpleBindRequest('foo@bar', 'bar', 5));

        $queue->sendMessage(Argument::any())->shouldNotBeCalled();

        $this->shouldThrow(OperationException::class)
            ->during(
                'handleBind',
                [$bind, $dispatcher, $queue]
            );
    }
}
