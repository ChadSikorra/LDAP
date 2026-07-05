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

namespace FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\Control\Sync\SyncRequestControl;

/**
 * @api
 */
final class Session
{
    public const PHASE_DELETE = 0;

    public const PHASE_PRESENT = 1;

    public const MODE_POLL = SyncRequestControl::MODE_REFRESH_ONLY;

    public const MODE_LISTEN = SyncRequestControl::MODE_REFRESH_AND_PERSIST;

    private bool $refreshDeletes = false;

    public function __construct(
        private readonly int $mode,
        private ?string $cookie,
        private ?int $phase = null,
        private bool $refreshComplete = false,
    ) {}

    /**
     * The cookie that represents this sync session.
     */
    public function getCookie(): ?string
    {
        return $this->cookie;
    }

    /**
     * The phase currently in progress for the sync session. One of:
     *
     *   - {@see self::PHASE_DELETE}
     *   - {@see self::PHASE_PRESENT}
     *
     * May return null if neither of those phases are currently active.
     */
    public function getPhase(): ?int
    {
        return $this->phase;
    }

    /**
     * The mode of the session. One of:
     *
     *   - {@see self::MODE_POLL}
     *   - {@see self::MODE_LISTEN}
     */
    public function getMode(): int
    {
        return $this->mode;
    }

    /**
     * Whether the initial refresh phase has completed. Once true, any later entries received are persist phase change
     * notifications rather than initial content.
     */
    public function isRefreshComplete(): bool
    {
        return $this->refreshComplete;
    }

    /**
     * Whether the completed refresh conveyed deletes explicitly (a delete-phase incremental refresh).
     *
     * When false, the refresh was a present phase whose deletes are implied by absence, so a consumer maintaining a
     * replica must delete local entries not seen during it. Only meaningful once {@see self::isRefreshComplete()}.
     */
    public function hasRefreshDeletes(): bool
    {
        return $this->refreshDeletes;
    }

    /**
     * @internal
     */
    public function updatePhase(?int $phase): self
    {
        $this->phase = $phase;

        return $this;
    }

    /**
     * @internal
     */
    public function markRefreshComplete(bool $refreshDeletes = false): self
    {
        $this->refreshComplete = true;
        $this->refreshDeletes = $refreshDeletes;

        return $this;
    }

    /**
     * @internal
     */
    public function resetRefreshState(): self
    {
        $this->phase = null;
        $this->refreshComplete = false;
        $this->refreshDeletes = false;

        return $this;
    }

    /**
     * @internal
     */
    public function updateCookie(?string $cookie): self
    {
        $this->cookie = $cookie;

        return $this;
    }
}
