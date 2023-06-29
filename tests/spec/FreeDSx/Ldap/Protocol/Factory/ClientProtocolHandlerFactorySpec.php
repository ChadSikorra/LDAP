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

namespace spec\FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Request\SyncRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshDelete;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientBasicHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientExtendedOperationHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientReferralHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientSaslBindHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientSearchHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientStartTlsHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientSyncHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientUnbindHandler;
use FreeDSx\Ldap\Protocol\Factory\ClientProtocolHandlerFactory;
use PhpSpec\ObjectBehavior;

class ClientProtocolHandlerFactorySpec extends ObjectBehavior
{
    public function it_is_initializable(): void
    {
        $this->shouldHaveType(ClientProtocolHandlerFactory::class);
    }

    public function it_should_get_a_search_response_handler(RequestInterface $request): void
    {
        $this->forResponse($request, new SearchResultEntry(new Entry('')))->shouldBeAnInstanceOf(ClientSearchHandler::class);
        $this->forResponse($request, new SearchResultDone(0))->shouldBeAnInstanceOf(ClientSearchHandler::class);
    }

    public function it_should_get_an_unbind_request_handler(): void
    {
        $this->forRequest(Operations::unbind())->shouldBeAnInstanceOf(ClientUnbindHandler::class);
    }

    public function it_should_get_a_basic_request_handler(): void
    {
        $this->forRequest(Operations::delete('cn=foo'))->shouldBeAnInstanceOf(ClientBasicHandler::class);
        $this->forRequest(Operations::bind('foo', 'bar'))->shouldBeAnInstanceOf(ClientBasicHandler::class);
        $this->forRequest(Operations::add(new Entry('')))->shouldBeAnInstanceOf(ClientBasicHandler::class);
        $this->forRequest(Operations::modify(new Entry('')))->shouldBeAnInstanceOf(ClientBasicHandler::class);
        $this->forRequest(Operations::move('cn=foo', 'cn=bar'))->shouldBeAnInstanceOf(ClientBasicHandler::class);
        $this->forRequest(Operations::cancel(1))->shouldBeAnInstanceOf(ClientBasicHandler::class);
        $this->forRequest(Operations::whoami())->shouldBeAnInstanceOf(ClientBasicHandler::class);
    }

    public function it_should_get_a_referral_handler(RequestInterface $request): void
    {
        $this->forResponse($request, new DeleteResponse(ResultCode::REFERRAL))->shouldBeAnInstanceOf(
            ClientReferralHandler::class
        );
    }

    public function it_should_get_an_extended_response_handler(RequestInterface $request): void
    {
        $this->forResponse($request, new ExtendedResponse(new LdapResult(0)))->shouldBeAnInstanceOf(
            ClientExtendedOperationHandler::class
        );
    }

    public function it_should_get_a_start_tls_handler(): void
    {
        $this->forResponse(new ExtendedRequest(ExtendedRequest::OID_START_TLS), new ExtendedResponse(new LdapResult(0), ExtendedRequest::OID_START_TLS))->shouldBeAnInstanceOf(
            ClientStartTlsHandler::class
        );
    }

    public function it_should_get_a_basic_response_handler(RequestInterface $request): void
    {
        $this->forResponse($request, new BindResponse(new LdapResult(0)))->shouldBeAnInstanceOf(
            ClientBasicHandler::class
        );
    }

    public function it_should_get_a_sasl_bind_handler(): void
    {
        $this->forRequest(new SaslBindRequest('DIGEST-MD5'))->shouldBeAnInstanceOf(
            ClientSaslBindHandler::class
        );
    }

    public function it_should_get_a_sync_handler_for_a_request(): void
    {
        $this->forRequest(new SyncRequest())
            ->shouldBeAnInstanceOf(ClientSyncHandler::class);
    }

    public function it_should_get_a_sync_handler_for_a_response(): void
    {
        $this->forResponse(
            new SyncRequest(),
            new SearchResultDone(0)
        )->shouldBeAnInstanceOf(ClientSyncHandler::class);
    }

    public function it_should_get_a_sync_handler_for_an_sync_info_response(): void
    {
        $this->forResponse(
            new SyncRequest(),
            new SyncRefreshDelete(),
        )->shouldBeAnInstanceOf(ClientSyncHandler::class);
    }
}
