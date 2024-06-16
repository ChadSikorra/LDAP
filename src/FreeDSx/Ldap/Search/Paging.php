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

namespace FreeDSx\Ldap\Search;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResponse;

/**
 * Provides a simple wrapper around paging a search operation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Paging
{
    private ?PagingControl $control = null;

    private bool $ended = false;

    private bool $isCritical = false;

    public function __construct(
        private LdapClient $client,
        private SearchRequest $search,
        private int $size = 1000,
    ) {
    }

    /**
     * Set the criticality of the control. Setting this will cause the LDAP server to return an error if paging is not
     * possible.
     */
    public function isCritical(bool $isCritical = true): self
    {
        $this->isCritical = $isCritical;

        return $this;
    }

    /**
     * Start a new paging operation with a search request. This must be called first if you reuse the paging object.
     */
    public function start(
        SearchRequest $search,
        ?int $size = null
    ): void {
        $this->size = $size ?? $this->size;
        $this->search = $search;
        $this->control = null;
        $this->ended = false;
    }

    /**
     * End the paging operation. This can be triggered at any time.
     *
     * @throws OperationException
     */
    public function end(): self
    {
        $this->send(0);
        $this->ended = true;

        return $this;
    }

    /**
     * Get the next set of entries of results.
     *
     * @return Entries<Entry>
     *
     * @throws OperationException
     */
    public function getEntries(?int $size = null): Entries
    {
        return $this->send($size);
    }

    public function hasEntries(): bool
    {
        if ($this->ended) {
            return false;
        }

        return $this->control === null || !($this->control->getCookie() === '');
    }

    /**
     * The size may be set to the server's estimate of the total number of entries in the entire result set. Servers
     * that cannot provide such an estimate may set this size to zero.
     */
    public function sizeEstimate(): ?int
    {
        return ($this->control !== null) ? $this->control->getSize() : null;
    }

    /**
     * @return Entries<Entry>
     *
     * @throws OperationException
     */
    private function send(?int $size = null): Entries
    {
        $cookie = ($this->control !== null)
            ? $this->control->getCookie()
            : '';
        $message = $this->client->sendAndReceive(
            $this->search,
            Controls::paging($size ?? $this->size, $cookie)
                ->setCriticality($this->isCritical)
        );
        $control = $message->controls()
            ->get(Control::OID_PAGING);

        if ($control !== null && !$control instanceof PagingControl) {
            throw new ProtocolException(sprintf(
                'Expected a paging control, but received: %s.',
                get_class($control)
            ));
        }
        # OpenLDAP returns no paging control in response to an abandon request. However, other LDAP implementations do;
        # such as Active Directory. It's not clear from the paging RFC which is correct.
        if ($control === null && $size !== 0 && $this->isCritical) {
            throw new ProtocolException('Expected a paging control, but received none.');
        }
        # The server does not support paging, but the control was not marked as critical. In this case the server will
        # return results but might ignore the control altogether.
        if ($control === null && $size !== 0 && !$this->isCritical) {
            $this->ended = true;
        }
        $this->control = $control;
        /** @var SearchResponse $response */
        $response = $message->getResponse();

        return $response->getEntries();
    }
}
