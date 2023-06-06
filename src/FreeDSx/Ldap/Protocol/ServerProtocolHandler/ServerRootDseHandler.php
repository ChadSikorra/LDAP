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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;
use function count;

/**
 * Handles RootDSE based search requests.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerRootDseHandler implements ServerProtocolHandlerInterface
{
    private ?RootDseHandlerInterface $rootDseHandler;

    public function __construct(?RootDseHandlerInterface $rootDseHandler = null)
    {
        $this->rootDseHandler = $rootDseHandler;
    }

    /**
     * {@inheritDoc}
     * @throws EncoderException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
        RequestHandlerInterface $dispatcher,
        ServerQueue $queue,
        ServerOptions $options
    ): void {
        $entry = Entry::fromArray('', [
            'namingContexts' => $options->getDseNamingContexts(),
            'supportedExtension' => [
                ExtendedRequest::OID_WHOAMI,
            ],
            'supportedLDAPVersion' => ['3'],
            'vendorName' => $options->getDseVendorName(),
        ]);
        if ($options->getSslCert()) {
            $entry->add(
                'supportedExtension',
                ExtendedRequest::OID_START_TLS
            );
        }
        if ($options->getPagingHandler()) {
            $entry->add(
                'supportedControl',
                Control::OID_PAGING
            );
        }
        if ($options->getDseVendorVersion()) {
            $entry->set('vendorVersion', (string) $options->getDseVendorVersion());
        }
        if ($options->getDseAltServer()) {
            $entry->set('altServer', (string) $options->getDseAltServer());
        }

        /** @var SearchRequest $request */
        $request = $message->getRequest();
        $this->filterEntryAttributes($request, $entry);

        if ($this->rootDseHandler) {
            $entry = $this->rootDseHandler->rootDse(
                new RequestContext($message->controls(), $token),
                $request,
                $entry
            );
        }

        $queue->sendMessage(
            new LdapMessageResponse(
                $message->getMessageId(),
                new SearchResultEntry($entry)
            ),
            new LdapMessageResponse(
                $message->getMessageId(),
                new SearchResultDone(ResultCode::SUCCESS)
            )
        );
    }

    /**
     * Filters attributes from an entry to return only what was requested.
     */
    private function filterEntryAttributes(
        SearchRequest $request,
        Entry $entry
    ): void {
        if (count($request->getAttributes()) !== 0) {
            foreach ($entry->getAttributes() as $dseAttr) {
                $found = false;
                foreach ($request->getAttributes() as $attribute) {
                    if ($attribute->equals($dseAttr)) {
                        $found = true;
                        break;
                    }
                }
                if ($found === true && $request->getAttributesOnly()) {
                    $dseAttr->reset();
                }
                if ($found === false) {
                    $entry->reset($dseAttr);
                    $entry->changes()->reset();
                }
            }
        }
        if ($request->getAttributesOnly()) {
            foreach ($entry->getAttributes() as $attribute) {
                $attribute->reset();
            }
        }
    }
}
