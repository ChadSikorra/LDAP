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

use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Session;

/**
 * Wraps an applier to drop a subject's replica-local password-policy state once the primary's authoritative entry
 * supersedes it, so the entry becomes the single source of truth.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ReconcilingChangeApplier implements ChangeApplierInterface
{
    public function __construct(
        private ChangeApplierInterface $baseApplier,
        private ReplicaPasswordStateStoreInterface $passwordStateStore,
    ) {}

    public function beginRefresh(): void
    {
        $this->baseApplier->beginRefresh();
    }

    public function apply(
        SyncEntryResult $result,
        Session $session,
    ): void {
        $this->baseApplier->apply($result, $session);

        // Only an add or modify carries authoritative state that can supersede local accumulation; present is a no-op
        // and a delete drops the subject, whose local state cascades with the entry row.
        if (!$result->isAdd() && !$result->isModify()) {
            return;
        }

        $this->passwordStateStore->discardIfSuperseded(
            $result->getEntry()->getDn()->normalize(),
            UserPasswordState::fromEntry($result->getEntry()),
        );
    }

    public function reconcile(): void
    {
        $this->baseApplier->reconcile();
    }
}
