<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerUnbindHandler;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ServerUnbindHandlerSpec extends ObjectBehavior
{
    public function it_is_initializable(): void
    {
        $this->shouldHaveType(ServerUnbindHandler::class);
    }

    public function it_should_handle_an_unbind_request(ServerQueue $queue, TokenInterface $token, RequestHandlerInterface $dispatcher): void
    {
        $queue->close()->shouldBeCalled();
        $queue->sendMessage(Argument::any())->shouldNotBeCalled();

        $unbind = new LdapMessageRequest(1, new UnbindRequest());
        $this->handleRequest($unbind, $token, $dispatcher, $queue, []);
    }
}
