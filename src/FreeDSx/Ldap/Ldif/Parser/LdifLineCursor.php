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

use function base64_decode;
use function count;
use function explode;
use function ltrim;
use function str_replace;
use function strpos;
use function strtolower;
use function substr;

/**
 * Cursor over LDIF lines exposing the shared low-level reading primitives.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class LdifLineCursor
{
    private const COMMENT = '#';

    private const SEPARATOR = ':';

    private const URL_MARKER = '<';

    /**
     * @param string[] $lines
     */
    private function __construct(
        private array $lines,
        private int $pos = 0,
    ) {}

    public static function forInput(string $ldif): self
    {
        return new self(explode(
            "\n",
            str_replace(
                ["\r\n", "\r"],
                "\n",
                $ldif,
            ),
        ));
    }

    public function atEnd(): bool
    {
        return $this->pos >= count($this->lines);
    }

    public function current(): string
    {
        return $this->lines[$this->pos];
    }

    public function position(): int
    {
        return $this->pos;
    }

    public function advance(): void
    {
        $this->pos++;
    }

    /**
     * Reads the directive at the cursor, consuming any folded continuation lines.
     *
     * @throws LdifParseException
     */
    public function readDirective(): LdifDirective
    {
        $at = $this->pos;
        $line = $this->lines[$at];
        $colon = strpos($line, self::SEPARATOR);

        if ($colon === false || $colon === 0) {
            $this->errorAt(
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
            $this->errorAt(
                $at,
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
            $at,
        );
    }

    /**
     * Appends any continuation lines (those beginning with a single space) to the value.
     */
    public function readFolded(string $value): string
    {
        while ($this->isAtContinuation()) {
            $value .= substr($this->current(), 1);
            $this->pos++;
        }

        return $value;
    }

    public function skipComment(): void
    {
        $this->pos++;

        while ($this->isAtContinuation()) {
            $this->pos++;
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
    public function decodeBase64(
        string $raw,
        int $at,
    ): string {
        $decoded = base64_decode($raw, true);

        if ($decoded === false) {
            $this->errorAt(
                $at,
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
            $this->pos,
            $message,
        );
    }

    /**
     * @throws LdifParseException
     */
    public function errorAt(
        int $at,
        string $message,
    ): never {
        throw new LdifParseException(
            $message,
            $at + 1,
            $this->lines[$at] ?? null,
        );
    }
}
