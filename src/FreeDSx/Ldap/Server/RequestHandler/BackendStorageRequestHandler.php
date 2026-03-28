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

namespace FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use FreeDSx\Ldap\Server\Paging\PagingResponse;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\Storage\FilterEvaluator;
use FreeDSx\Ldap\Server\Storage\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Storage\ReadableStorageAdapterInterface;
use FreeDSx\Ldap\Server\Storage\WritableStorageAdapterInterface;
use SensitiveParameter;

/**
 * A request handler that delegates all LDAP operations to a storage adapter.
 *
 * Implements both RequestHandlerInterface and PagingHandlerInterface so a
 * single instance can be registered for both via LdapServer::useStorageAdapter().
 *
 * Write operations (add, delete, modify, modifyDn) are rejected with
 * unwillingToPerform if the adapter does not implement WritableStorageAdapterInterface.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class BackendStorageRequestHandler implements RequestHandlerInterface, PagingHandlerInterface
{
    private readonly FilterEvaluatorInterface $filterEvaluator;

    /**
     * Per-request paging state: cookie => remaining entries.
     *
     * @var array<string, Entry[]>
     */
    private array $pagingState = [];

    public function __construct(
        private readonly ReadableStorageAdapterInterface $adapter,
        ?FilterEvaluatorInterface $filterEvaluator = null,
    ) {
        $this->filterEvaluator = $filterEvaluator ?? new FilterEvaluator();
    }

    public function search(
        RequestContext $context,
        SearchRequest $search,
    ): Entries {
        $baseDn = $search->getBaseDn();

        if ($baseDn === null) {
            throw new OperationException('No base DN provided.', ResultCode::PROTOCOL_ERROR);
        }

        $candidates = $this->adapter->list($baseDn, $search->getScope());
        $filter = $search->getFilter();
        $requestedAttrs = $search->getAttributes();
        $typesOnly = $search->getAttributesOnly();

        $results = [];
        foreach ($candidates as $entry) {
            if ($this->filterEvaluator->evaluate($entry, $filter)) {
                $results[] = $this->applyAttributeFilter($entry, $requestedAttrs, $typesOnly);
            }
        }

        return new Entries(...$results);
    }

    public function add(
        RequestContext $context,
        AddRequest $add,
    ): void {
        $adapter = $this->requireWritable();
        $entry = $add->getEntry();

        if ($this->adapter->get($entry->getDn()) !== null) {
            throw new OperationException(
                sprintf('Entry already exists: %s', $entry->getDn()->toString()),
                ResultCode::ENTRY_ALREADY_EXISTS
            );
        }

        $adapter->add($entry);
    }

    public function delete(
        RequestContext $context,
        DeleteRequest $delete,
    ): void {
        $adapter = $this->requireWritable();
        $dn = $delete->getDn();

        if ($this->adapter->get($dn) === null) {
            throw new OperationException(
                sprintf('No such object: %s', $dn->toString()),
                ResultCode::NO_SUCH_OBJECT
            );
        }

        // Refuse to delete entries that have children (non-leaf)
        $children = $this->adapter->list($dn, SearchRequest::SCOPE_SINGLE_LEVEL);
        if (count($children) > 0) {
            throw new OperationException(
                sprintf('Entry "%s" has subordinate entries and cannot be deleted.', $dn->toString()),
                ResultCode::NOT_ALLOWED_ON_NON_LEAF
            );
        }

        $adapter->delete($dn);
    }

    public function modify(
        RequestContext $context,
        ModifyRequest $modify,
    ): void {
        $adapter = $this->requireWritable();
        $dn = $modify->getDn();

        if ($this->adapter->get($dn) === null) {
            throw new OperationException(
                sprintf('No such object: %s', $dn->toString()),
                ResultCode::NO_SUCH_OBJECT
            );
        }

        $adapter->update($dn, $modify->getChanges());
    }

    public function modifyDn(
        RequestContext $context,
        ModifyDnRequest $modifyDn,
    ): void {
        $adapter = $this->requireWritable();
        $dn = $modifyDn->getDn();

        if ($this->adapter->get($dn) === null) {
            throw new OperationException(
                sprintf('No such object: %s', $dn->toString()),
                ResultCode::NO_SUCH_OBJECT
            );
        }

        $adapter->move(
            $dn,
            $modifyDn->getNewRdn(),
            $modifyDn->getDeleteOldRdn(),
            $modifyDn->getNewParentDn(),
        );
    }

    public function compare(
        RequestContext $context,
        CompareRequest $compare,
    ): bool {
        $entry = $this->adapter->get($compare->getDn());

        if ($entry === null) {
            throw new OperationException(
                sprintf('No such object: %s', $compare->getDn()->toString()),
                ResultCode::NO_SUCH_OBJECT
            );
        }

        return $this->filterEvaluator->evaluate($entry, $compare->getFilter());
    }

    public function extended(
        RequestContext $context,
        ExtendedRequest $extended,
    ): void {
        throw new OperationException(
            sprintf('Extended operation not supported: %s', $extended->getName()),
            ResultCode::UNWILLING_TO_PERFORM
        );
    }

    public function bind(
        string $username,
        #[SensitiveParameter]
        string $password,
    ): bool {
        return $this->adapter->verifyPassword(
            new \FreeDSx\Ldap\Entry\Dn($username),
            $password
        );
    }

    public function page(
        PagingRequest $pagingRequest,
        RequestContext $context,
    ): PagingResponse {
        $cookie = $pagingRequest->getCookie();

        if ($pagingRequest->isPagingStart()) {
            // First page: run the full search and cache results
            $allEntries = $this->search($context, $pagingRequest->getSearchRequest());
            $remaining = $allEntries->toArray();
        } else {
            $remaining = $this->pagingState[$cookie] ?? [];
        }

        $size = $pagingRequest->getSize();
        $page = array_splice($remaining, 0, $size > 0 ? $size : count($remaining));

        if (count($remaining) === 0) {
            unset($this->pagingState[$cookie]);

            return PagingResponse::makeFinal(new Entries(...$page));
        }

        $newCookie = $pagingRequest->getNextCookie();
        $this->pagingState[$newCookie] = $remaining;

        return PagingResponse::make(new Entries(...$page), count($remaining));
    }

    public function remove(
        PagingRequest $pagingRequest,
        RequestContext $context,
    ): void {
        unset($this->pagingState[$pagingRequest->getCookie()]);
        unset($this->pagingState[$pagingRequest->getNextCookie()]);
    }

    private function requireWritable(): WritableStorageAdapterInterface
    {
        if (!($this->adapter instanceof WritableStorageAdapterInterface)) {
            throw new OperationException(
                'This operation is not supported by a read-only storage adapter.',
                ResultCode::UNWILLING_TO_PERFORM
            );
        }

        return $this->adapter;
    }

    /**
     * Filter the attributes on an entry according to the requested attribute list.
     *
     * An empty list means return all attributes. The special value "*" also means
     * all attributes. "1.1" means return no attributes (just the DN).
     *
     * @param Attribute[] $requestedAttrs
     */
    private function applyAttributeFilter(
        Entry $entry,
        array $requestedAttrs,
        bool $typesOnly,
    ): Entry {
        $names = array_map(
            static fn(Attribute $a): string => strtolower($a->getDescription()),
            $requestedAttrs
        );

        $returnAll = count($names) === 0 || in_array('*', $names, true);
        $returnNone = count($names) === 1 && $names[0] === '1.1';

        $filteredAttributes = [];

        foreach ($entry->getAttributes() as $attribute) {
            if ($returnNone) {
                break;
            }

            if (!$returnAll && !in_array(strtolower($attribute->getDescription()), $names, true)) {
                continue;
            }

            if ($typesOnly) {
                $filteredAttributes[] = new Attribute($attribute->getName());
            } else {
                $filteredAttributes[] = $attribute;
            }
        }

        return new Entry($entry->getDn(), ...$filteredAttributes);
    }
}
