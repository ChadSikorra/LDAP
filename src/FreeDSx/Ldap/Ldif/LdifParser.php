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

namespace FreeDSx\Ldap\Ldif;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\LdifParseException;
use FreeDSx\Ldap\Ldif\Loader\LdifLoaderInterface;
use FreeDSx\Ldap\Ldif\Loader\StringLdifLoader;
use FreeDSx\Ldap\Ldif\Parser\LdifChangeRecordParser;
use FreeDSx\Ldap\Ldif\Parser\LdifLineCursor;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operations;
use Generator;

use function sprintf;

/**
 * Parses RFC 2849 LDIF (content and change records) into a unified collection of write requests.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class LdifParser
{
    private const DN = 'dn';

    private const VERSION = 'version';

    private const CHANGETYPE = 'changetype';

    public function __construct(
        private readonly LdifChangeRecordParser $changeParser = new LdifChangeRecordParser(),
    ) {}

    /**
     * Streams parsed write requests from an LDIF source.
     *
     * @return Generator<RequestInterface>
     * @throws LdifParseException
     */
    public function parse(LdifLoaderInterface $loader): Generator
    {
        $cursor = LdifLineCursor::forLoader($loader);
        $recordsSeen = 0;

        while (!$cursor->atEnd()) {
            $line = $cursor->current();

            if ($line === '') {
                $cursor->advance();
                continue;
            }
            if ($cursor->isComment($line)) {
                $cursor->skipComment();
                continue;
            }

            $key = $cursor->keyOf($line);

            if ($key === self::DN) {
                yield $this->parseRecord($cursor);

                $recordsSeen++;
            } elseif ($key === self::VERSION) {
                $this->assertVersion($cursor, $recordsSeen);
            } else {
                $cursor->error('Expected a "dn:" line to begin a record');
            }
        }
    }

    /**
     * Convenience for parsing an in-memory LDIF string.
     *
     * @return Generator<RequestInterface>
     * @throws LdifParseException
     */
    public static function parseString(string $ldif): Generator
    {
        return (new self())
            ->parse(new StringLdifLoader($ldif));
    }

    /**
     * @throws LdifParseException
     */
    private function parseRecord(LdifLineCursor $cursor): RequestInterface
    {
        $dn = $cursor->readDirective()->value;

        return $this->isAtChangetype($cursor)
            ? $this->changeParser->parseRecord($cursor, $dn)
            : $this->parseContentRecord($cursor, $dn);
    }

    /**
     * @throws LdifParseException
     */
    private function parseContentRecord(
        LdifLineCursor $cursor,
        string $dn,
    ): AddRequest {
        /** @var array<string, string[]> $attributes */
        $attributes = [];

        while (!$cursor->atEnd()) {
            $line = $cursor->current();

            if ($line === '') {
                break;
            }
            if ($cursor->isComment($line)) {
                $cursor->skipComment();
                continue;
            }
            if ($cursor->keyOf($line) === self::DN) {
                break;
            }

            $directive = $cursor->readDirective();

            if ($directive->is(self::CHANGETYPE)) {
                $cursor->errorFor(
                    $directive,
                    '"changetype:" must be the first directive after dn',
                );
            }

            $attributes[$directive->name][] = $directive->value;
        }

        return Operations::add(Entry::create(
            $dn,
            $attributes,
        ));
    }

    /**
     * Peeks (after skipping comments) whether the next directive is "changetype:".
     */
    private function isAtChangetype(LdifLineCursor $cursor): bool
    {
        while (!$cursor->atEnd() && $cursor->isComment($cursor->current())) {
            $cursor->skipComment();
        }

        if ($cursor->atEnd() || $cursor->current() === '') {
            return false;
        }

        return $cursor->keyOf($cursor->current()) === self::CHANGETYPE;
    }

    /**
     * @throws LdifParseException
     */
    private function assertVersion(
        LdifLineCursor $cursor,
        int $recordsSeen,
    ): void {
        $at = $cursor->position();
        $sourceLine = $cursor->current();

        if ($recordsSeen !== 0) {
            $cursor->errorAt(
                $at,
                $sourceLine,
                'The version directive must appear before any records',
            );
        }

        $version = $cursor->readDirective()->value;

        if ($version !== '1') {
            $cursor->errorAt(
                $at,
                $sourceLine,
                sprintf(
                    'Unsupported LDIF version "%s"',
                    $version,
                ),
            );
        }
    }
}
