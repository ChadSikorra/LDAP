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

namespace FreeDSx\Ldap\Sync\Provider;

use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncNewCookie;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Read\ChangeScope;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Read\ChangeStream;
use FreeDSx\Ldap\Server\Clock\Sleeper;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Tails the change journal for a refreshAndPersist consumer, pushing changes until it cancels or disconnects.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SyncPersistStreamer
{
    /**
     * Seconds between journal polls; also bounds change-delivery latency and dead-peer detection.
     */
    public const DEFAULT_POLL_INTERVAL = 1.0;

    public function __construct(
        private ServerQueue $queue,
        private LdapBackendInterface $backend,
        private SyncResultProjector $projector,
        private ChangeStream $stream,
        private Sleeper $sleeper,
        private float $pollInterval = self::DEFAULT_POLL_INTERVAL,
    ) {}

    /**
     * The net effect of journal changes since a sequence, as sync results (adds and deletes).
     *
     * @return iterable<SyncResult>
     */
    public function projectSince(
        int $sinceSeq,
        SearchRequest $request,
        TokenInterface $token,
    ): iterable {
        $scope = $this->scopeFor($request);
        $netByUuid = [];

        foreach ($this->stream->since($sinceSeq, $scope) as $record) {
            $netByUuid[$record->change->entryUuid] = $record->change;
        }

        foreach ($netByUuid as $change) {
            $result = $change->changeType === ChangeType::Delete
                ? $this->projector->projectDeleted($change, $request, $token)
                : $this->fetchAndProject($change, $request, $token);

            if ($result !== null) {
                yield $result;
            }
        }
    }

    /**
     * Runs the persist phase: pushes each change as it lands, advancing the cookie, until cancel or disconnect.
     */
    public function persist(
        int $startSeq,
        SearchRequest $request,
        TokenInterface $token,
        int $messageId,
        Dn $baseDn,
    ): void {
        $lastSeq = $startSeq;
        $origin = $this->stream->origin();

        while (true) {
            $latestSeq = $this->stream->latestSeq();

            // A trim past the consumer's position would silently drop changes: force a full re-sync instead.
            if ($latestSeq > $lastSeq && !$this->stream->retainsSince($lastSeq)) {
                $this->sendRefreshRequired($messageId, $baseDn, $origin, $latestSeq);

                return;
            }

            if ($latestSeq > $lastSeq) {
                $this->pushChanges($lastSeq, $request, $token, $messageId);
                $lastSeq = $latestSeq;
            }

            // Advances the client cookie, and doubles as a keepalive that surfaces a dead peer on the next poll.
            $this->queue->sendMessage(new LdapMessageResponse(
                $messageId,
                new SyncNewCookie((new SyncCookie($origin, $lastSeq))->encode()),
            ));

            $signal = $this->queue->peekForCancelSignal($messageId);

            if ($signal !== null) {
                $this->sendTerminal($signal, $messageId, $baseDn, $origin, $lastSeq);

                return;
            }

            $this->sleeper->sleep($this->pollInterval);
        }
    }

    private function pushChanges(
        int $sinceSeq,
        SearchRequest $request,
        TokenInterface $token,
        int $messageId,
    ): void {
        foreach ($this->projectSince($sinceSeq, $request, $token) as $result) {
            $this->queue->sendMessage(new LdapMessageResponse(
                $messageId,
                $result->entry,
                $result->control,
            ));
        }
    }

    private function fetchAndProject(
        PendingChange $change,
        SearchRequest $request,
        TokenInterface $token,
    ): ?SyncResult {
        $entry = $this->backend->get($change->dn);

        if ($entry === null) {
            return null;
        }

        return $this->projector->projectFetched(
            $entry,
            $request,
            $token,
        );
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

    private function sendTerminal(
        LdapMessageRequest $signal,
        int $messageId,
        Dn $baseDn,
        ReplicaId $origin,
        int $lastSeq,
    ): void {
        // Abandon carries no response (RFC 4511 §4.11); only a Cancel gets an acknowledged close.
        if (!($signal->getRequest() instanceof CancelRequest)) {
            return;
        }

        $this->queue->sendMessage(
            new LdapMessageResponse(
                $messageId,
                new SearchResultDone(
                    ResultCode::CANCELED,
                    $baseDn->toString(),
                ),
                new SyncDoneControl(
                    (new SyncCookie($origin, $lastSeq))->encode(),
                    true,
                ),
            ),
            new LdapMessageResponse(
                $signal->getMessageId(),
                new ExtendedResponse(new LdapResult(ResultCode::SUCCESS)),
            ),
        );
    }

    private function sendRefreshRequired(
        int $messageId,
        Dn $baseDn,
        ReplicaId $origin,
        int $latestSeq,
    ): void {
        $this->queue->sendMessage(new LdapMessageResponse(
            $messageId,
            new SearchResultDone(
                ResultCode::SYNCHRONIZATION_REFRESH_REQUIRED,
                $baseDn->toString(),
            ),
            new SyncDoneControl(
                (new SyncCookie($origin, $latestSeq))->encode(),
                true,
            ),
        ));
    }
}
