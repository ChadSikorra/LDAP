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

namespace FreeDSx\Ldap\Ldif\Parser;

use FreeDSx\Ldap\Exception\LdifParseException;
use FreeDSx\Ldap\Ldif\Loader\LdifLoaderInterface;
use Generator;

use function base64_decode;
use function ltrim;
use function preg_split;
use function strpos;
use function strtolower;
use function substr;

/**
 * Streaming cursor over LDIF lines exposing the shared low-level reading primitives.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class LdifLineCursor
{
    private const COMMENT = '#';

    private const SEPARATOR = ':';

    private const URL_MARKER = '<';

    private ?string $current = null;

    private int $lineNumber = 0;

    /**
     * @param Generator<int, string> $source
     */
    private function __construct(private readonly Generator $source)
    {
        $this->source->rewind();
        $this->advance();
    }

    /**
     * @param iterable<string> $lines
     */
    public static function forIterable(iterable $lines): self
    {
        return new self(self::toGenerator($lines));
    }

    public static function forInput(string $ldif): self
    {
        $lines = preg_split("/\r\n|\r|\n/", $ldif);

        return self::forIterable($lines === false ? [] : $lines);
    }

    public static function forLoader(LdifLoaderInterface $loader): self
    {
        return self::forIterable($loader->load());
    }

    public function atEnd(): bool
    {
        return $this->current === null;
    }

    public function current(): string
    {
        return $this->current ?? '';
    }

    public function position(): int
    {
        return $this->lineNumber;
    }

    public function advance(): void
    {
        if (!$this->source->valid()) {
            $this->current = null;

            return;
        }

        $this->current = $this->source->current();
        $this->lineNumber++;
        $this->source->next();
    }

    /**
     * @param iterable<string> $lines
     * @return Generator<int, string>
     */
    private static function toGenerator(iterable $lines): Generator
    {
        foreach ($lines as $line) {
            yield $line;
        }
    }

    /**
     * Reads the directive at the cursor, consuming any folded continuation lines.
     *
     * @throws LdifParseException
     */
    public function readDirective(): LdifDirective
    {
        $startLine = $this->lineNumber;
        $startSource = $this->current;
        $line = $this->current ?? '';
        $colon = strpos($line, self::SEPARATOR);

        if ($colon === false || $colon === 0) {
            $this->errorAt(
                $startLine,
                $startSource,
                'Expected a "name: value" directive',
            );
        }

        $name = substr($line, 0, $colon);
        $marker = $line[$colon + 1] ?? '';
        $this->advance();

        if ($marker === self::SEPARATOR) {
            $value = $this->decodeBase64(
                $this->readFolded(ltrim(
                    substr($line, $colon + 2),
                    ' ',
                )),
                $startLine,
                $startSource,
            );
        } elseif ($marker === self::URL_MARKER) {
            $this->errorAt(
                $startLine,
                $startSource,
                'URL-referenced values ("name:< url") are not yet supported',
            );
        } else {
            $value = $this->readFolded(ltrim(
                substr($line, $colon + 1),
                ' ',
            ));
        }

        return new LdifDirective(
            $name,
            $value,
            $startLine,
            $startSource,
        );
    }

    /**
     * Appends any continuation lines (those beginning with a single space) to the value.
     */
    public function readFolded(string $value): string
    {
        while ($this->isAtContinuation()) {
            $value .= substr($this->current(), 1);
            $this->advance();
        }

        return $value;
    }

    public function skipComment(): void
    {
        $this->advance();

        while ($this->isAtContinuation()) {
            $this->advance();
        }
    }

    public function isComment(string $line): bool
    {
        return ($line[0] ?? '') === self::COMMENT;
    }

    /**
     * A continuation line (RFC 2849 §2): a non-empty current line that begins with a single space.
     */
    public function isAtContinuation(): bool
    {
        return !$this->atEnd()
            && $this->current() !== ''
            && $this->current()[0] === ' ';
    }

    public function keyOf(string $line): string
    {
        $colon = strpos($line, self::SEPARATOR);

        return $colon === false
            ? ''
            : strtolower(substr($line, 0, $colon));
    }

    /**
     * @throws LdifParseException
     */
    private function decodeBase64(
        string $raw,
        int $line,
        ?string $sourceLine,
    ): string {
        $decoded = base64_decode($raw, true);

        if ($decoded === false) {
            $this->errorAt(
                $line,
                $sourceLine,
                'A base64-encoded value is not valid',
            );
        }

        return $decoded;
    }

    /**
     * @throws LdifParseException
     */
    public function error(string $message): never
    {
        $this->errorAt(
            $this->lineNumber,
            $this->current,
            $message,
        );
    }

    /**
     * @throws LdifParseException
     */
    public function errorAt(
        int $line,
        ?string $sourceLine,
        string $message,
    ): never {
        throw new LdifParseException(
            $message,
            $line,
            $sourceLine,
        );
    }

    /**
     * @throws LdifParseException
     */
    public function errorFor(
        LdifDirective $directive,
        string $message,
    ): never {
        $this->errorAt(
            $directive->position,
            $directive->sourceLine,
            $message,
        );
    }
}
