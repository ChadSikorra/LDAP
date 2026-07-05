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

namespace FreeDSx\Ldap\Sync\Consumer;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Session;

/**
 * Applies sync results verbatim to a local replica's raw storage, reconciling deletes by absence.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class VerbatimStorageApplier implements ChangeApplierInterface
{
    /**
     * @var array<string, true> Normalized DNs seen during the current refresh phase.
     *
     * @todo Held entirely in memory, so a full refresh of a very large directory is costly. Should be refactored to a
     *       threshold-based on-disk (or generation-marked) present-set.
     */
    private array $presentDns = [];

    public function __construct(private readonly EntryStorageInterface $storage) {}

    public function beginRefresh(): void
    {
        $this->presentDns = [];
    }

    public function apply(
        SyncEntryResult $result,
        Session $session,
    ): void {
        $entry = $result->getEntry();
        $dn = $entry->getDn()
            ->normalize();

        if ($result->isDelete()) {
            $this->storage->remove($dn);

            return;
        }

        if (!$session->isRefreshComplete()) {
            $this->presentDns[$dn->toString()] = true;
        }

        if ($result->isPresent()) {
            return;
        }

        $this->storage->store($entry);
    }

    public function reconcile(): void
    {
        $options = StorageListOptions::matchAll(
            new Dn(''),
            subtree: true,
        );

        $stale = [];
        foreach ($this->storage->list($options)->entries as $entry) {
            $dn = $entry->getDn()
                ->normalize();

            if (!isset($this->presentDns[$dn->toString()])) {
                $stale[] = $dn;
            }
        }

        foreach ($stale as $dn) {
            $this->storage->remove($dn);
        }

        $this->presentDns = [];
    }
}
