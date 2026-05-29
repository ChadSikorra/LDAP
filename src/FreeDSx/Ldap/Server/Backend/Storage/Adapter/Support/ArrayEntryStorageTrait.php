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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\TimeLimitExceededException;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use Generator;

/**
 * Scope-filtered list helpers for array-backed stores; composes DefaultHasChildrenTrait (use that directly for DB-backed adapters).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait ArrayEntryStorageTrait
{
    use DefaultHasChildrenTrait;

    /**
     * @param array<string, Entry> $entries Entries keyed by normalised DN string
     */
    private function listFromArray(
        StorageListOptions $options,
        array $entries,
    ): EntryStream {
        if ($options->sortKeys === []) {
            return new EntryStream(
                $this->yieldByScope(
                    $entries,
                    $options->baseDn,
                    $options->subtree,
                    $options->timeLimit,
                ),
            );
        }

        return new EntryStream($this->sortedStreamFromArray(
            $options,
            $entries,
        ));
    }

    /**
     * @param array<string, Entry> $entries Entries keyed by normalised DN string
     * @return Generator<Entry>
     */
    private function sortedStreamFromArray(
        StorageListOptions $options,
        array $entries,
    ): Generator {
        /** @var list<Entry> $collected */
        $collected = iterator_to_array(
            $this->yieldByScope(
                $entries,
                $options->baseDn,
                $options->subtree,
                $options->timeLimit,
            ),
            false,
        );

        yield from (new SortKeyComparator())->sort(
            $collected,
            $options->sortKeys,
        );
    }

    /**
     * @param array<string, Entry> $entries Entries keyed by normalised DN string
     * @return list<Dn>
     */
    private function namingContextsFromArray(array $entries): array
    {
        $roots = [];
        foreach (array_keys($entries) as $normDn) {
            $parent = (new Dn($normDn))->getParent()?->normalize()->toString() ?? '';
            if ($parent === '' || !isset($entries[$parent])) {
                $roots[] = new Dn($normDn);
            }
        }

        return $roots;
    }

    /**
     * @param array<string, Entry> $entries Entries keyed by normalised DN string
     * @return Generator<Entry>
     */
    private function yieldByScope(
        array $entries,
        Dn $baseDn,
        bool $subtree,
        int $timeLimit = 0,
    ): Generator {
        $deadline = $timeLimit > 0
            ? microtime(true) + $timeLimit
            : null;

        foreach ($entries as $normDn => $entry) {
            if ($deadline !== null && microtime(true) >= $deadline) {
                throw new TimeLimitExceededException();
            }

            $entryDn = new Dn($normDn);

            if ($subtree && $entryDn->isDescendantOf($baseDn)) {
                yield $entry;
            } elseif (!$subtree && $entryDn->isChildOf($baseDn)) {
                yield $entry;
            }
        }
    }
}
