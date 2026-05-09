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

namespace FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\TimeLimitExceededException;
use FreeDSx\Ldap\Server\SearchLimits;
use Generator;

/**
 * Builds EntryStreams for search operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SearchStreamBuilder
{
    public function __construct(
        private EntryStorageInterface $storage,
        private SearchLimits $limits = new SearchLimits(),
    ) {}

    public function effectiveTimeLimit(int $requestLimit): int
    {
        $serverMax = $this->limits->maxSearchTimeLimit;

        if ($serverMax === 0) {
            return $requestLimit;
        }

        if ($requestLimit === 0) {
            return $serverMax;
        }

        return min(
            $requestLimit,
            $serverMax,
        );
    }

    public function buildForBaseObject(
        Entry $entry,
        SearchRequest $request,
    ): EntryStream {
        $entry = $this->requestsHasSubordinates($request)
            ? $this->injectHasSubordinates($entry)
            : $entry;

        return new EntryStream($this->yieldSingle($entry));
    }

    /**
     * @throws OperationException
     */
    public function buildForList(
        EntryStream $stream,
        SearchRequest $request,
    ): EntryStream {
        $generator = $this->wrapWithTimeLimitHandling($stream->entries);

        if ($this->requestsHasSubordinates($request)) {
            $generator = $this->wrapWithHasSubordinates($generator);
        }

        return new EntryStream(
            $generator,
            $stream->isPreFiltered,
        );
    }

    private function requestsHasSubordinates(SearchRequest $request): bool
    {
        foreach ($request->getAttributes() as $attr) {
            if ($this->isHasSubordinatesAttribute($attr)) {
                return true;
            }
        }

        return false;
    }

    private function isHasSubordinatesAttribute(Attribute $attr): bool
    {
        return strcasecmp($attr->getName(), '+') === 0
            || strcasecmp($attr->getName(), 'hasSubordinates') === 0;
    }

    private function injectHasSubordinates(Entry $entry): Entry
    {
        $clone = clone $entry;
        $clone->set(
            'hasSubordinates',
            $this->storage->hasChildren($entry->getDn())
                ? 'TRUE'
                : 'FALSE',
        );

        return $clone;
    }

    /**
     * @param Generator<Entry> $generator
     * @return Generator<Entry>
     */
    private function wrapWithHasSubordinates(Generator $generator): Generator
    {
        foreach ($generator as $entry) {
            yield $this->injectHasSubordinates($entry);
        }
    }

    /**
     * @param Generator<Entry> $generator
     * @return Generator<Entry>
     * @throws OperationException
     */
    private function wrapWithTimeLimitHandling(Generator $generator): Generator
    {
        try {
            foreach ($generator as $entry) {
                yield $entry;
            }
        } catch (TimeLimitExceededException) {
            throw new OperationException(
                'Time limit exceeded.',
                ResultCode::TIME_LIMIT_EXCEEDED,
            );
        }
    }

    /**
     * @return Generator<Entry>
     */
    private function yieldSingle(Entry $entry): Generator
    {
        yield $entry;
    }
}
