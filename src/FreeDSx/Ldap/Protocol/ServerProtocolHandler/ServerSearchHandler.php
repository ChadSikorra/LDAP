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

use FreeDSx\Ldap\Control\Sorting\SortingResponseControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use FreeDSx\Ldap\Server\Operation\SearchOperationResult;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use Generator;

/**
 * Handles search request logic.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerSearchHandler implements ServerProtocolHandlerInterface
{
    use ServerSearchTrait;

    private const CANCEL_CHECK_INTERVAL = 50;

    public function __construct(
        private readonly ServerQueue $queue,
        private readonly LdapBackendInterface $backend,
        private readonly FilterEvaluatorInterface $filterEvaluator,
        private readonly AccessControlInterface $accessControl,
        private readonly Schema $schema,
        private readonly SearchLimits $limits = new SearchLimits(),
    ) {}

    /**
     * @inheritDoc
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): OperationResult {
        $request = $this->getSearchRequestFromMessage($message);
        $state = new SearchResultState();

        $this->assertBaseDnProvided($request);

        $backendResult = $this->backend->search(
            $request,
            $this->controlsForBackend($message),
            $this->limits,
        );

        $projection = AttributeProjection::forRequest(
            $request->getAttributes(),
            $request->getAttributesOnly(),
            $this->schema,
        );
        $searchResult = SearchResult::makeSuccessResult(
            $this->filteredEntryStream(
                $backendResult,
                $request,
                $state,
                $token,
                $message->getMessageId(),
                $projection,
            ),
            (string) $request->getBaseDn(),
            $state,
        );

        $sortControl = $this->sortingControl($message);
        $responseControls = $sortControl !== null
            ? [new SortingResponseControl(0)]
            : [];

        $this->sendEntriesToClient(
            $searchResult,
            $message,
            $this->queue,
            ...$responseControls,
        );

        return SearchOperationResult::success(
            $message,
            $state->entriesReturned,
        );
    }

    /**
     * Streams filtered + attribute-projected entries from the backend.
     *
     * Checks for cancel signals periodically.
     *
     * @return Generator<Entry>
     */
    private function filteredEntryStream(
        EntryStream $backend,
        SearchRequest $request,
        SearchResultState $state,
        TokenInterface $token,
        int $messageId,
        AttributeProjection $projection,
    ): Generator {
        $sizeLimit = $this->effectiveSizeLimit(
            $request->getSizeLimit(),
            $this->limits->maxSearchSize,
        );
        $filter = $request->getFilter();
        $emitted = 0;

        foreach ($backend->entries as $entry) {
            if ($this->shouldCancelSearch($emitted, $messageId, $state)) {
                return;
            }

            $filtered = $this->accessControl->filterEntry(
                $token,
                $entry,
            );

            if ($filtered === null) {
                continue;
            }

            if ($filtered !== $entry && !$this->filterEvaluator->evaluate($filtered, $filter)) {
                continue;
            }

            yield $projection->project($filtered);
            $emitted++;
            $state->entriesReturned++;

            if ($sizeLimit > 0 && $emitted >= $sizeLimit) {
                $state->resultCode = ResultCode::SIZE_LIMIT_EXCEEDED;

                return;
            }
        }
    }

    private function shouldCancelSearch(
        int $emitted,
        int $messageId,
        SearchResultState $state,
    ): bool {
        if ($emitted === 0 || $emitted % self::CANCEL_CHECK_INTERVAL !== 0) {
            return false;
        }

        $signal = $this->queue->peekForCancelSignal($messageId);
        if ($signal === null) {
            return false;
        }

        $request = $signal->getRequest();
        if ($request instanceof AbandonRequest) {
            $state->isAbandoned = true;

            return true;
        }

        if ($request instanceof CancelRequest) {
            $state->cancelSignal = $signal;
        }

        return true;
    }
}
