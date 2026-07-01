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

use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\Server\Utility\Uuid;

/**
 * Turns a live entry or a journal change into an RFC 4533 sync result, applying read-side ACL and filter matching.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SyncResultProjector
{
    public function __construct(
        private AccessControlInterface $accessControl,
        private FilterEvaluatorInterface $filterEvaluator,
        private EventLogger $eventLogger = new EventLogger(null),
    ) {}

    /**
     * A search result (already filter-matched by the backend) as an add, if the consumer may see it.
     */
    public function projectSearched(
        Entry $entry,
        TokenInterface $token,
    ): ?SyncResult {
        $visible = $this->accessControl->filterEntry(
            $token,
            $entry,
        );

        if ($visible === null) {
            return null;
        }

        return $this->addResult($visible);
    }

    /**
     * A freshly fetched changed entry as an add, if the consumer may see it and it still matches the filter.
     */
    public function projectFetched(
        Entry $entry,
        SearchRequest $request,
        TokenInterface $token,
    ): ?SyncResult {
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

        return $this->addResult($visible);
    }

    /**
     * A delete, announced only if the consumer could have seen the entry (checked against its pre-image), so a
     * gone entry never leaks a DN/UUID the read-side ACL would have hidden.
     */
    public function projectDeleted(
        PendingChange $change,
        SearchRequest $request,
        TokenInterface $token,
    ): ?SyncResult {
        if (!$this->wasVisible($request, $token, $change->preImage)) {
            return null;
        }

        $binaryUuid = $this->binaryUuidOrSkip(
            $change->entryUuid,
            $change->dn,
        );

        if ($binaryUuid === null) {
            return null;
        }

        return new SyncResult(
            new SearchResultEntry(new Entry($change->dn)),
            new SyncStateControl(
                SyncStateControl::STATE_DELETE,
                $binaryUuid,
            ),
        );
    }

    private function addResult(Entry $entry): ?SyncResult
    {
        $uuid = $entry->get(AttributeTypeOid::NAME_ENTRY_UUID)?->firstValue();

        if ($uuid === null || $uuid === '') {
            return null;
        }

        $binaryUuid = $this->binaryUuidOrSkip(
            $uuid,
            $entry->getDn(),
        );

        if ($binaryUuid === null) {
            return null;
        }

        return new SyncResult(
            new SearchResultEntry($entry),
            new SyncStateControl(
                SyncStateControl::STATE_ADD,
                $binaryUuid,
            ),
        );
    }

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
     * The 16-byte UUID for a sync state control, or null (skipping the entry) when the stored entryUUID is
     * malformed, so one corrupt value cannot abort the whole stream.
     */
    private function binaryUuidOrSkip(
        string $uuid,
        Dn $dn,
    ): ?string {
        try {
            return Uuid::toBinary($uuid);
        } catch (InvalidArgumentException) {
            $this->eventLogger->record(
                ServerEvent::SyncEntrySkipped,
                [
                    EventContext::DN => $dn->toString(),
                    EventContext::REASON => 'invalid entryUUID',
                ],
            );

            return null;
        }
    }
}
