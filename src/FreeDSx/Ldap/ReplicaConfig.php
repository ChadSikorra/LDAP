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

namespace FreeDSx\Ldap;

use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Sync\Consumer\Checkpoint\InMemoryReplicationCheckpoint;
use FreeDSx\Ldap\Sync\Consumer\Checkpoint\ReplicationCheckpointInterface;

/**
 * Configures a server as a replica of an upstream primary.
 *
 * Replicas currently act as read-only.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ReplicaConfig
{
    public function __construct(
        private readonly ClientOptions $primary,
        private readonly ReplicationCheckpointInterface $checkpoint = new InMemoryReplicationCheckpoint(),
        private ?FilterInterface $filter = null,
        private bool $referWrites = true,
    ) {}

    /**
     * The client options for connecting to the upstream primary (servers, TLS, credentials, base DN).
     */
    public function getPrimary(): ClientOptions
    {
        return $this->primary;
    }

    /**
     * Where the sync cookie is persisted so the replica resumes across restarts.
     */
    public function getCheckpoint(): ReplicationCheckpointInterface
    {
        return $this->checkpoint;
    }

    /**
     * The filter selecting which entries to replicate, or null for all in-scope entries.
     */
    public function getFilter(): ?FilterInterface
    {
        return $this->filter;
    }

    public function setFilter(?FilterInterface $filter): self
    {
        $this->filter = $filter;

        return $this;
    }

    /**
     * Whether a client write is referred to the primary (true) or hard-rejected (false).
     */
    public function shouldReferWrites(): bool
    {
        return $this->referWrites;
    }

    public function setReferWrites(bool $referWrites): self
    {
        $this->referWrites = $referWrites;

        return $this;
    }

    /**
     * The primary's LDAP URLs, for referring client writes upstream.
     *
     * @return list<LdapUrl>
     */
    public function referralUrls(): array
    {
        $urls = [];

        foreach ($this->primary->getServers() as $server) {
            $urls[] = (new LdapUrl($server))
                ->setPort($this->primary->getPort())
                ->setUseSsl($this->primary->isUseSsl());
        }

        return $urls;
    }
}
