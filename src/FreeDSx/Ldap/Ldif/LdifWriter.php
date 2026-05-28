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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;

use function array_map;
use function array_merge;
use function array_values;
use function base64_encode;
use function implode;
use function max;
use function preg_match;
use function str_split;
use function strlen;
use function substr;

/**
 * Serializes entries to RFC 2849 LDIF content records.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LdifWriter
{
    public function __construct(private LdifOutputOptions $options = new LdifOutputOptions()) {}

    /**
     * @param iterable<Entry> $entries
     */
    public function write(iterable $entries): string
    {
        $blocks = [];

        foreach ($entries as $entry) {
            $blocks[] = $this->entryBlock($entry);
        }

        $body = implode($this->options->getLineEnding(), $blocks);

        return $this->options->isIncludeVersion()
            ? 'version: 1' . $this->options->getLineEnding() . $this->options->getLineEnding() . $body
            : $body;
    }

    private function entryBlock(Entry $entry): string
    {
        $lines = array_merge(
            [$this->line('dn', $entry->getDn()->toString())],
            ...array_map(
                $this->attributeLines(...),
                $entry->getAttributes(),
            ),
        );

        return implode($this->options->getLineEnding(), $lines) . $this->options->getLineEnding();
    }

    /**
     * @return list<string>
     */
    private function attributeLines(Attribute $attribute): array
    {
        return array_values(array_map(
            fn(string $value): string => $this->line(
                $attribute->getDescription(),
                $value,
            ),
            $attribute->getValues(),
        ));
    }

    private function line(
        string $attribute,
        string $value,
    ): string {
        if ($value === '') {
            return $attribute . ':';
        }
        if ($this->needsBase64($value)) {
            return $this->fold($attribute . ':: ' . base64_encode($value));
        }

        return $this->fold($attribute . ': ' . $value);
    }

    /**
     * A value is not SAFE-STRING (RFC 2849 §2) when it begins with a space, ':' or '<', ends with a space, or holds a
     * NUL/CR/LF or any non-ASCII byte.
     */
    private function needsBase64(string $value): bool
    {
        $first = $value[0];

        if ($first === ' ' || $first === ':' || $first === '<') {
            return true;
        }
        if ($value[strlen($value) - 1] === ' ') {
            return true;
        }

        return preg_match('/[^\x01-\x7F]|[\x0A\x0D]/', $value) === 1;
    }

    private function fold(string $line): string
    {
        $maxLineLength = $this->options->getMaxLineLength();

        if (!$this->options->isLineFolding() || strlen($line) <= $maxLineLength) {
            return $line;
        }

        $folded = substr($line, 0, $maxLineLength);
        $continuationLength = max(1, $maxLineLength - 1);

        foreach (str_split(substr($line, $maxLineLength), $continuationLength) as $chunk) {
            $folded .= $this->options->getLineEnding() . ' ' . $chunk;
        }

        return $folded;
    }
}
