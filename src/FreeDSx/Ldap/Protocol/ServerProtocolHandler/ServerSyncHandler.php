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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Read\ChangeScope;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Read\ChangeStream;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use FreeDSx\Ldap\Server\Operation\SearchOperationResult;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\Server\Utility\Uuid;
use FreeDSx\Ldap\Sync\Provider\Exception\MalformedSyncCookieException;
use FreeDSx\Ldap\Sync\Provider\SyncCookie;
use Generator;

/**
 * Serves RFC 4533 content-synchronization (refreshOnly) from the change journal.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ServerSyncHandler implements ServerProtocolHandlerInterface
{
    use ServerSearchTrait;

    public function __construct(
        private readonly ServerQueue $queue,
        private readonly LdapBackendInterface $backend,
        private readonly FilterEvaluatorInterface $filterEvaluator,
        private readonly AccessControlInterface $accessControl,
        private readonly SearchLimits $limits = new SearchLimits(),
        private readonly ?ChangeStream $changeStream = null,
    ) {}

    /**
     * @throws OperationException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): OperationResult {
        $request = $this->getSearchRequestFromMessage($message);
        $control = $this->syncRequestControl($message);
        $stream = $this->changeStream;

        if ($stream === null) {
            throw new OperationException(
                'Content synchronization is not supported.',
                ResultCode::UNWILLING_TO_PERFORM,
            );
        }

        if ($control->getMode() !== SyncRequestControl::MODE_REFRESH_ONLY) {
            throw new OperationException(
                'Only refreshOnly content synchronization is supported.',
                ResultCode::UNWILLING_TO_PERFORM,
            );
        }

        $baseDn = $this->assertBaseDnProvided($request);
        $latestSeq = $stream->latestSeq();
        $sinceSeq = $this->resolveSince($control, $stream, $latestSeq);
        $state = new SearchResultState();

        $entries = $sinceSeq === null
            ? $this->fullRefreshEntries($message, $request, $token, $state)
            : $this->incrementalEntries($message, $request, $token, $stream, $sinceSeq, $state);

        // refreshDeletes: a delete phase (true) only for an incremental sync that sent explicit
        // deletes; a full refresh is a present phase (false) the consumer reconciles by absence.
        $doneControl = new SyncDoneControl(
            (new SyncCookie($stream->origin(), $latestSeq))->encode(),
            $sinceSeq !== null,
        );
        $this->queue->sendMessages($this->withSyncDone(
            $entries,
            $message->getMessageId(),
            $baseDn,
            $doneControl,
        ));

        return SearchOperationResult::success(
            $message,
            $state->entriesReturned,
        );
    }

    /**
     * @param Generator<LdapMessageResponse> $entries
     * @return Generator<LdapMessageResponse>
     */
    private function withSyncDone(
        Generator $entries,
        int $messageId,
        Dn $baseDn,
        SyncDoneControl $doneControl,
    ): Generator {
        yield from $entries;

        yield new LdapMessageResponse(
            $messageId,
            new SearchResultDone(
                ResultCode::SUCCESS,
                $baseDn->toString(),
            ),
            $doneControl,
        );
    }

    /**
     * Empty/unknown cookie: every in-scope live entry as an add.
     *
     * @return Generator<LdapMessageResponse>
     */
    private function fullRefreshEntries(
        LdapMessageRequest $message,
        SearchRequest $request,
        TokenInterface $token,
        SearchResultState $state,
    ): Generator {
        $result = $this->backend->search(
            $request,
            $this->controlsForBackend($message),
            $this->limits,
        );

        foreach ($result->entries as $entry) {
            $visible = $this->accessControl->filterEntry(
                $token,
                $entry,
            );

            if ($visible === null) {
                continue;
            }

            yield from $this->emit(
                $this->addResponse($message->getMessageId(), $visible),
                $state,
            );
        }
    }

    /**
     * Valid cookie: the net effect per entry since its seq, as adds and deletes.
     *
     * @return Generator<LdapMessageResponse>
     */
    private function incrementalEntries(
        LdapMessageRequest $message,
        SearchRequest $request,
        TokenInterface $token,
        ChangeStream $stream,
        int $sinceSeq,
        SearchResultState $state,
    ): Generator {
        $netByUuid = [];

        foreach ($stream->since($sinceSeq, $this->scopeFor($request)) as $record) {
            $netByUuid[$record->change->entryUuid] = $record->change;
        }

        foreach ($netByUuid as $change) {
            $response = $change->changeType === ChangeType::Delete
                ? $this->deleteResponse($message->getMessageId(), $request, $token, $change)
                : $this->changedEntryResponse($message->getMessageId(), $request, $token, $change);

            yield from $this->emit($response, $state);
        }
    }

    private function addResponse(
        int $messageId,
        Entry $entry,
    ): ?LdapMessageResponse {
        $uuid = $entry->get(AttributeTypeOid::NAME_ENTRY_UUID)?->firstValue();

        if ($uuid === null || $uuid === '') {
            return null;
        }

        return new LdapMessageResponse(
            $messageId,
            new SearchResultEntry($entry),
            new SyncStateControl(
                SyncStateControl::STATE_ADD,
                Uuid::toBinary($uuid),
            ),
        );
    }

    /**
     * The delete is announced only if the consumer could have seen the entry, checked against its
     * pre-image, so a gone entry never leaks a DN/UUID the read-side ACL would have hidden.
     */
    private function deleteResponse(
        int $messageId,
        SearchRequest $request,
        TokenInterface $token,
        PendingChange $change,
    ): ?LdapMessageResponse {
        if (!$this->wasVisible($request, $token, $change->preImage)) {
            return null;
        }

        return new LdapMessageResponse(
            $messageId,
            new SearchResultEntry(new Entry($change->dn)),
            new SyncStateControl(
                SyncStateControl::STATE_DELETE,
                Uuid::toBinary($change->entryUuid),
            ),
        );
    }

    private function changedEntryResponse(
        int $messageId,
        SearchRequest $request,
        TokenInterface $token,
        PendingChange $change,
    ): ?LdapMessageResponse {
        $entry = $this->backend->get($change->dn);

        if ($entry === null) {
            return null;
        }

        $visible = $this->accessControl->filterEntry(
            $token,
            $entry,
        );

        if ($visible === null) {
            return null;
        }

        if (!$this->filterEvaluator->evaluate($visible, $request->getFilter())) {
            return null;
        }

        return $this->addResponse(
            $messageId,
            $visible,
        );
    }

    /**
     * Whether the entry, as it was before deletion, was readable by and matched the consumer's view.
     */
    private function wasVisible(
        SearchRequest $request,
        TokenInterface $token,
        ?Entry $preImage,
    ): bool {
        if ($preImage === null) {
            return false;
        }

        $visible = $this->accessControl->filterEntry(
            $token,
            $preImage,
        );

        return $visible !== null
            && $this->filterEvaluator->evaluate($visible, $request->getFilter());
    }

    /**
     * @return Generator<LdapMessageResponse>
     */
    private function emit(
        ?LdapMessageResponse $response,
        SearchResultState $state,
    ): Generator {
        if ($response === null) {
            return;
        }

        $state->entriesReturned++;

        yield $response;
    }

    private function resolveSince(
        SyncRequestControl $control,
        ChangeStream $stream,
        int $latestSeq,
    ): ?int {
        $cookie = $control->getCookie();

        if ($cookie === null || $cookie === '' || $control->getReloadHint()) {
            return null;
        }

        try {
            $decoded = SyncCookie::decode($cookie);
        } catch (MalformedSyncCookieException) {
            return null;
        }

        if (!$decoded->origin->equals($stream->origin()) || $decoded->seq > $latestSeq) {
            return null;
        }

        return $decoded->seq;
    }

    private function scopeFor(SearchRequest $request): ChangeScope
    {
        $baseDn = $request->getBaseDn() ?? new Dn('');

        return match ($request->getScope()) {
            SearchRequest::SCOPE_BASE_OBJECT => ChangeScope::baseObject($baseDn),
            SearchRequest::SCOPE_SINGLE_LEVEL => ChangeScope::oneLevel($baseDn),
            default => ChangeScope::wholeSubtree($baseDn),
        };
    }

    /**
     * @throws OperationException
     */
    private function syncRequestControl(LdapMessageRequest $message): SyncRequestControl
    {
        $control = $message->controls()->get(Control::OID_SYNC_REQUEST);

        if (!$control instanceof SyncRequestControl) {
            throw new OperationException(
                'The sync request control was expected, but not received.',
                ResultCode::PROTOCOL_ERROR,
            );
        }

        return $control;
    }
}
