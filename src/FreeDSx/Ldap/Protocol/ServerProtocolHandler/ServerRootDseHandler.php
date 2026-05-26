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
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use FreeDSx\Ldap\Server\RequestContext;
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
    /**
     * RFC 3673 §3 — return all operational attributes via the "+" attribute description.
     */
    private const FEATURE_OID_ALL_OPERATIONAL_ATTRS = '1.3.6.1.4.1.4203.1.5.1';

    /**
     * RFC 4526 — absolute True ("(&)") and False ("(|)") filters.
     */
    private const FEATURE_OID_ABSOLUTE_TRUE_FALSE_FILTERS = '1.3.6.1.4.1.4203.1.5.3';

    public function __construct(
        private readonly ServerOptions $options,
        private readonly ServerQueue $queue,
        private readonly ?RootDseHandlerInterface $rootDseHandler = null,
    ) {}

    /**
     * {@inheritDoc}
     * @throws EncoderException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): OperationResult {
        $entry = Entry::fromArray('', [
            'namingContexts' => $this->options->getDseNamingContexts(),
            'subschemaSubentry' => [$this->options->getSubschemaEntry()->toString()],
            'supportedControl' => [
                Control::OID_PAGING,
                Control::OID_SORTING,
                Control::OID_RELAX_RULES,
                Control::OID_PROXY_AUTHORIZATION,
            ],
            'supportedExtension' => [
                ExtendedRequest::OID_WHOAMI,
                ExtendedRequest::OID_PWD_MODIFY,
                ExtendedRequest::OID_CANCEL,
            ],
            'supportedFeatures' => [
                self::FEATURE_OID_ALL_OPERATIONAL_ATTRS,
                self::FEATURE_OID_ABSOLUTE_TRUE_FALSE_FILTERS,
            ],
            'supportedLDAPVersion' => ['3'],
            'vendorName' => $this->options->getDseVendorName(),
        ]);
        if ($this->options->getSslCert()) {
            $entry->add(
                'supportedExtension',
                ExtendedRequest::OID_START_TLS,
            );
        }
        if ($this->options->getDseVendorVersion()) {
            $entry->set('vendorVersion', (string) $this->options->getDseVendorVersion());
        }
        if (!empty($this->options->getSaslMechanisms())) {
            $entry->set('supportedSaslMechanisms', ...$this->options->getSaslMechanisms());
        }
        if ($this->options->getDseAltServer()) {
            $entry->set('altServer', (string) $this->options->getDseAltServer());
        }

        /** @var SearchRequest $request */
        $request = $message->getRequest();
        if ($this->rootDseHandler) {
            $entry = $this->rootDseHandler->rootDse(
                new RequestContext($message->controls(), $token),
                $request,
                $entry,
            );
        }

        $this->filterEntryAttributes($request, $entry);

        $this->queue->sendMessage(
            new LdapMessageResponse(
                $message->getMessageId(),
                new SearchResultEntry($entry),
            ),
            new LdapMessageResponse(
                $message->getMessageId(),
                new SearchResultDone(ResultCode::SUCCESS),
            ),
        );

        return OperationOutcomeResult::succeeded();
    }

    /**
     * Filters attributes from an entry to return only what was requested.
     */
    private function filterEntryAttributes(
        SearchRequest $request,
        Entry $entry,
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
