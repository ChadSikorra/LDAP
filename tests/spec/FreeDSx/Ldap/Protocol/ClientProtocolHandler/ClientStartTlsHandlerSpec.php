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

namespace spec\FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientStartTlsHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ResponseHandlerInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use PhpSpec\ObjectBehavior;

class ClientStartTlsHandlerSpec extends ObjectBehavior
{
    public function let(ClientQueue $queue): void
    {
        $this->beConstructedWith($queue);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(ClientStartTlsHandler::class);
    }

    public function it_should_implement_ResponseHandlerInterface(): void
    {
        $this->shouldBeAnInstanceOf(ResponseHandlerInterface::class);
    }

    public function it_should_encrypt_the_queue_if_the_message_response_is_successful(ClientQueue $queue): void
    {
        $startTls = new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_START_TLS));
        $response = new LdapMessageResponse(1, new ExtendedResponse(new LdapResult(0), ExtendedRequest::OID_START_TLS));

        $queue->encrypt()->shouldBeCalledOnce()->willReturn($queue);
        $this->handleResponse($startTls, $response)->shouldBeAnInstanceOf(LdapMessageResponse::class);
    }

    public function it_should_throw_an_exception_if_the_message_response_is_unsuccessful(ClientQueue $queue): void
    {
        $startTls = new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_START_TLS));
        $response = new LdapMessageResponse(1, new ExtendedResponse(new LdapResult(ResultCode::UNAVAILABLE_CRITICAL_EXTENSION), ExtendedRequest::OID_START_TLS));

        $queue->encrypt(true)->shouldNotBeCalled();
        $this->shouldThrow(ConnectionException::class)->during('handleResponse', [$startTls, $response, $queue, new ClientOptions()]);
    }
}
