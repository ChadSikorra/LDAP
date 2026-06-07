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

namespace Tests\Support\FreeDSx\Ldap\Backend;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\SearchLimits;
use Generator;

/**
 * Stub backend keyed by DN string. Records how many times each DN is fetched so tests can assert caching.
 */
final class RecordingLdapBackend implements LdapBackendInterface
{
    /**
     * @var array<string, int>
     */
    private array $getCalls = [];

    /**
     * @param array<string, Entry> $entries DN string → entry
     */
    public function __construct(private readonly array $entries = []) {}

    public function get(Dn $dn): ?Entry
    {
        $key = $dn->toString();
        $this->getCalls[$key] = ($this->getCalls[$key] ?? 0) + 1;

        return $this->entries[$key] ?? null;
    }

    public function getCallCount(string $dn): int
    {
        return $this->getCalls[$dn] ?? 0;
    }

    public function search(
        SearchRequest $request,
        ControlBag $controls = new ControlBag(),
        ?SearchLimits $effectiveLimits = null,
    ): EntryStream {
        return new EntryStream((static function (): Generator {
            yield from [];
        })());
    }

    public function compare(
        Dn $dn,
        EqualityFilter $filter,
    ): bool {
        return false;
    }

    public function namingContexts(): array
    {
        return [];
    }
}
