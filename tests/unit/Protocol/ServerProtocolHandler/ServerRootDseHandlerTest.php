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
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerRootDseHandler;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerRootDseHandlerTest extends TestCase
{
    private ServerQueue&MockObject $mockQueue;

    private ServerRootDseHandler $subject;

    private TokenInterface&MockObject $mockToken;

    private ServerOptions $options;

    private RootDseHandlerInterface&MockObject $mockDseHandler;

    private LdapBackendInterface&MockObject $mockBackend;

    protected function setUp(): void
    {
        $this->options = new ServerOptions();
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockDseHandler = $this->createMock(RootDseHandlerInterface::class);
        $this->withBackendNamingContexts([]);
    }

    public function test_it_should_send_back_a_RootDSE(): void
    {
        $this->options->setDseVendorName('Foo');
        $this->withBackendNamingContexts(['dc=Foo,dc=Bar']);

        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope(),
        );

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                self::equalTo(new LdapMessageResponse(1, new SearchResultEntry(Entry::create('', [
                    'namingContexts' => 'dc=Foo,dc=Bar',
                    'subschemaSubentry' => ['cn=Subschema'],
                    'supportedControl' => [
                        Control::OID_PAGING,
                        Control::OID_SORTING,
                        Control::OID_RELAX_RULES,
                        Control::OID_PROXY_AUTHORIZATION,
                        Control::OID_ASSERTION,
                        Control::OID_PRE_READ,
                        Control::OID_POST_READ,
                        Control::OID_SUBTREE_DELETE,
                        Control::OID_SYNC_REQUEST,
                    ],
                    'supportedExtension' => [
                        ExtendedRequest::OID_WHOAMI,
                        ExtendedRequest::OID_PWD_MODIFY,
                        ExtendedRequest::OID_CANCEL,
                    ],
                    'supportedFeatures' => [
                        '1.3.6.1.4.1.4203.1.5.1',
                        '1.3.6.1.4.1.4203.1.5.3',
                    ],
                    'supportedLDAPVersion' => ['3'],
                    'vendorName' => 'Foo',
                ])))),
                self::equalTo(new LdapMessageResponse(1, new SearchResultDone(0))),
            );

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }

    public function test_it_always_advertises_paging_and_password_modify(): void
    {
        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope(),
        );

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                self::callback(function (LdapMessageResponse $response) {
                    /** @var SearchResultEntry $result */
                    $result = $response->getResponse();
                    $entry = $result->getEntry();

                    return $entry->get('supportedControl')?->has(Control::OID_PAGING) === true
                        && $entry->get('supportedExtension')?->has(ExtendedRequest::OID_PWD_MODIFY) === true;
                }),
                self::anything(),
            );

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }

    public function test_it_advertises_the_sync_control_when_sync_is_enabled(): void
    {
        $this->subject = new ServerRootDseHandler(
            $this->options,
            $this->mockQueue,
            $this->mockBackend,
            null,
            true,
        );

        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope(),
        );

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                self::callback(function (LdapMessageResponse $response) {
                    /** @var SearchResultEntry $result */
                    $result = $response->getResponse();

                    return $result->getEntry()->get('supportedControl')?->has(Control::OID_SYNC_REQUEST) === true;
                }),
                self::anything(),
            );

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }

    public function test_it_should_send_a_request_to_the_dispatcher_if_it_implements_a_rootdse_aware_interface(): void
    {
        $this->options->setDseVendorName('Foo');
        $this->withBackendNamingContexts(['dc=Foo,dc=Bar']);

        $this->subject = new ServerRootDseHandler(
            $this->options,
            $this->mockQueue,
            $this->mockBackend,
            $this->mockDseHandler,
        );

        $searchReqeust = (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope();
        $search = new LdapMessageRequest(
            1,
            $searchReqeust,
        );
        $rootDse = Entry::create('', [
            'namingContexts' => 'dc=Foo,dc=Bar',
            'subschemaSubentry' => ['cn=Subschema'],
            'supportedControl' => [
                Control::OID_PAGING,
                Control::OID_SORTING,
                Control::OID_RELAX_RULES,
                Control::OID_PROXY_AUTHORIZATION,
                Control::OID_ASSERTION,
                Control::OID_PRE_READ,
                Control::OID_POST_READ,
                Control::OID_SUBTREE_DELETE,
                Control::OID_SYNC_REQUEST,
            ],
            'supportedExtension' => [
                ExtendedRequest::OID_WHOAMI,
                ExtendedRequest::OID_PWD_MODIFY,
                ExtendedRequest::OID_CANCEL,
            ],
            'supportedFeatures' => [
                '1.3.6.1.4.1.4203.1.5.1',
                '1.3.6.1.4.1.4203.1.5.3',
            ],
            'supportedLDAPVersion' => ['3'],
            'vendorName' => 'Foo',
        ]);

        $handlerRootDse = Entry::fromArray('', ['foo' => 'bar']);

        $this->mockDseHandler
            ->expects($this->once())
            ->method('rootDse')
            ->with(
                self::isInstanceOf(RequestContext::class),
                $searchReqeust,
                $rootDse,
            )
            ->willReturn($handlerRootDse);

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                new LdapMessageResponse(1, new SearchResultEntry($handlerRootDse)),
                new LdapMessageResponse(1, new SearchResultDone(0)),
            );

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }

    public function test_it_should_include_supported_sasl_mechanisms_when_configured(): void
    {
        $this->options
            ->setSaslMechanisms(ServerOptions::SASL_PLAIN, ServerOptions::SASL_CRAM_MD5);

        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope(),
        );

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                self::callback(function (LdapMessageResponse $response) {
                    /** @var SearchResultEntry $search */
                    $search = $response->getResponse();
                    $attribute = $search->getEntry()->get('supportedSaslMechanisms');

                    return $attribute !== null
                        && $attribute->has(ServerOptions::SASL_PLAIN)
                        && $attribute->has(ServerOptions::SASL_CRAM_MD5);
                }),
                new LdapMessageResponse(
                    1,
                    new SearchResultDone(0),
                ),
            );

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }

    public function test_it_should_only_return_attribute_names_from_the_RootDSE_if_requested(): void
    {
        $this->options->setDseVendorName('Foo');
        $this->withBackendNamingContexts(['dc=Foo,dc=Bar']);

        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))
                ->base('')
                ->useBaseScope()
                ->setAttributesOnly(true),
        );

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                new LdapMessageResponse(1, new SearchResultEntry(Entry::create('', [
                    'namingContexts' => [],
                    'subschemaSubentry' => [],
                    'supportedControl' => [],
                    'supportedExtension' => [],
                    'supportedFeatures' => [],
                    'supportedLDAPVersion' => [],
                    'vendorName' => [],
                ]))),
                new LdapMessageResponse(1, new SearchResultDone(0)),
            );

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }

    public function test_it_advertises_subschema_subentry_in_rootdse(): void
    {
        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope(),
        );

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                self::callback(function (LdapMessageResponse $response) {
                    /** @var SearchResultEntry $result */
                    $result = $response->getResponse();
                    $attr = $result->getEntry()->get('subschemaSubentry');

                    return $attr !== null && $attr->has('cn=Subschema');
                }),
                self::anything(),
            );

        $this->subject->handleRequest($search, $this->mockToken);
    }

    public function test_it_uses_configured_subschema_entry_dn(): void
    {
        $this->options->setSubschemaEntry(new Dn('cn=schema,dc=example,dc=com'));

        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))->base('')->useBaseScope(),
        );

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                self::callback(function (LdapMessageResponse $response) {
                    /** @var SearchResultEntry $result */
                    $result = $response->getResponse();
                    $attr = $result->getEntry()->get('subschemaSubentry');

                    return $attr !== null && $attr->has('cn=schema,dc=example,dc=com');
                }),
                self::anything(),
            );

        $this->subject->handleRequest($search, $this->mockToken);
    }

    public function test_it_should_only_return_specific_attributes_from_the_RootDSE_if_requested(): void
    {
        $this->options->setDseVendorName('Foo');
        $this->withBackendNamingContexts(['dc=Foo,dc=Bar']);

        $search = new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))
                ->base('')
                ->useBaseScope()
                ->setAttributes('namingcontexts'),
        );

        # The reset below is needed, unfortunately, to properly test due to how the objects change...
        $entry = Entry::create('', ['namingContexts' => 'dc=Foo,dc=Bar', ]);
        $entry->changes()->reset();
        $entry->get('namingContexts')?->equals(new Attribute('foo'));

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                new LdapMessageResponse(
                    1,
                    new SearchResultEntry($entry),
                ),
                new LdapMessageResponse(1, new SearchResultDone(0)),
            );

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }

    /**
     * @param list<string> $dns
     */
    private function withBackendNamingContexts(array $dns): void
    {
        $this->mockBackend = $this->createMock(LdapBackendInterface::class);
        $this->mockBackend
            ->method('namingContexts')
            ->willReturn(array_map(
                fn(string $dn): Dn => new Dn($dn),
                $dns,
            ));

        $this->subject = new ServerRootDseHandler(
            $this->options,
            $this->mockQueue,
            $this->mockBackend,
            null,
        );
    }
}
