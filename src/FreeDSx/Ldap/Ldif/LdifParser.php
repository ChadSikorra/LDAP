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

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\LdifParseException;

use function base64_decode;
use function count;
use function explode;
use function ltrim;
use function str_replace;
use function strpos;
use function strtolower;
use function substr;

/**
 * Parses RFC 2849 LDIF content records (entries) into {@see Entries}.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class LdifParser
{
    private const COMMENT = '#';

    private const SEPARATOR = ':';

    private const URL_MARKER = '<';

    private const DN = 'dn';

    private const VERSION = 'version';

    private const CHANGETYPE = 'changetype';

    /**
     * @var string[]
     */
    private array $lines = [];

    private int $pos = 0;

    /**
     * @var Entry[]
     */
    private array $entries = [];

    /**
     * @throws LdifParseException
     */
    public function parse(string $ldif): Entries
    {
        $this->init($ldif);

        while (!$this->atEnd()) {
            $this->parseLine();
        }

        return new Entries(...$this->entries);
    }

    private function parseLine(): void
    {
        $line = $this->current();

        if ($line === '') {
            $this->pos++;

            return;
        }
        if ($this->isComment($line)) {
            $this->skipComment();

            return;
        }

        $key = $this->keyOf($line);

        if ($key === self::DN) {
            $this->entries[] = $this->parseEntry();
        } elseif ($key === self::VERSION) {
            $this->assertVersion();
        } else {
            throw $this->error('Expected a "dn:" line to begin an entry');
        }
    }

    /**
     * @throws LdifParseException
     */
    private function parseEntry(): Entry
    {
        [, $dn] = $this->readDirective();

        /** @var array<string, string[]> $attributes */
        $attributes = [];

        while (!$this->atEnd()) {
            $line = $this->current();

            if ($line === '') {
                break;
            }
            if ($this->isComment($line)) {
                $this->skipComment();

                continue;
            }
            if ($this->keyOf($line) === self::DN) {
                break;
            }

            $at = $this->pos;
            [$attribute, $value] = $this->readDirective();

            if (strtolower($attribute) === self::CHANGETYPE) {
                throw $this->errorAt(
                    $at,
                    'LDIF change records are not yet supported.',
                );
            }

            $attributes[$attribute][] = $value;
        }

        return Entry::create(
            $dn,
            $attributes,
        );
    }

    /**
     * Read the directive at the cursor, consuming any folded continuation lines.
     *
     * @return array{0: string, 1: string}
     * @throws LdifParseException
     */
    private function readDirective(): array
    {
        $at = $this->pos;
        $line = $this->lines[$at];
        $colon = strpos($line, self::SEPARATOR);

        if ($colon === false || $colon === 0) {
            throw $this->errorAt(
                $at,
                'Expected a "name: value" directive',
            );
        }

        $name = substr($line, 0, $colon);
        $marker = $line[$colon + 1] ?? '';
        $this->pos++;

        if ($marker === self::SEPARATOR) {
            $value = $this->decodeBase64(
                $this->readFolded(ltrim(
                    substr($line, $colon + 2),
                    ' ',
                )),
                $at,
            );
        } elseif ($marker === self::URL_MARKER) {
            throw $this->errorAt(
                $at,
                'URL-referenced values ("name:< url") are not yet supported',
            );
        } else {
            $value = $this->readFolded(ltrim(
                substr($line, $colon + 1),
                ' ',
            ));
        }

        return [$name, $value];
    }

    /**
     * Append any continuation lines (those beginning with a single space) to the value.
     */
    private function readFolded(string $value): string
    {
        while ($this->isAtContinuation()) {
            $value .= substr($this->current(), 1);
            $this->pos++;
        }

        return $value;
    }

    private function skipComment(): void
    {
        $this->pos++;

        while ($this->isAtContinuation()) {
            $this->pos++;
        }
    }

    /**
     * @throws LdifParseException
     */
    private function assertVersion(): void
    {
        $at = $this->pos;

        if (count($this->entries) !== 0) {
            throw $this->errorAt($at, 'The version directive must appear before any entries');
        }

        [, $version] = $this->readDirective();

        if ($version !== '1') {
            throw $this->errorAt($at, sprintf('Unsupported LDIF version "%s"', $version));
        }
    }

    /**
     * @throws LdifParseException
     */
    private function decodeBase64(
        string $raw,
        int $at,
    ): string {
        $decoded = base64_decode($raw, true);

        if ($decoded === false) {
            throw $this->errorAt(
                $at,
                'A base64-encoded value is not valid',
            );
        }

        return $decoded;
    }

    private function keyOf(string $line): string
    {
        $colon = strpos($line, self::SEPARATOR);

        return $colon === false
            ? ''
            : strtolower(substr($line, 0, $colon));
    }

    private function isComment(string $line): bool
    {
        return ($line[0] ?? '') === self::COMMENT;
    }

    /**
     * A continuation line (RFC 2849 §2): a non-empty current line that begins with a single space.
     */
    private function isAtContinuation(): bool
    {
        return !$this->atEnd()
            && $this->current() !== ''
            && $this->current()[0] === ' ';
    }

    private function atEnd(): bool
    {
        return $this->pos >= count($this->lines);
    }

    private function current(): string
    {
        return $this->lines[$this->pos];
    }

    private function error(string $message): LdifParseException
    {
        return $this->errorAt($this->pos, $message);
    }

    private function errorAt(
        int $at,
        string $message,
    ): LdifParseException {
        return new LdifParseException(
            $message,
            $at + 1,
            $this->lines[$at] ?? null,
        );
    }

    private function init(string $ldif): void
    {
        $this->lines = explode(
            "\n",
            str_replace(
                ["\r\n", "\r"],
                "\n",
                $ldif,
            ),
        );
        $this->pos = 0;
    }
}
