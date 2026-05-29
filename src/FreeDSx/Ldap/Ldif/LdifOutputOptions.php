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

/**
 * Output options for {@see LdifWriter}.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class LdifOutputOptions
{
    private bool $includeVersion = true;

    private bool $lineFolding = true;

    private int $maxLineLength = 76;

    private string $lineEnding = "\n";

    private bool $emitChangetypeForAdds = false;

    public function isIncludeVersion(): bool
    {
        return $this->includeVersion;
    }

    public function setIncludeVersion(bool $includeVersion): self
    {
        $this->includeVersion = $includeVersion;

        return $this;
    }

    public function isLineFolding(): bool
    {
        return $this->lineFolding;
    }

    public function setLineFolding(bool $lineFolding): self
    {
        $this->lineFolding = $lineFolding;

        return $this;
    }

    public function getMaxLineLength(): int
    {
        return $this->maxLineLength;
    }

    public function setMaxLineLength(int $maxLineLength): self
    {
        $this->maxLineLength = $maxLineLength;

        return $this;
    }

    public function getLineEnding(): string
    {
        return $this->lineEnding;
    }

    public function setLineEnding(string $lineEnding): self
    {
        $this->lineEnding = $lineEnding;

        return $this;
    }

    public function isEmitChangetypeForAdds(): bool
    {
        return $this->emitChangetypeForAdds;
    }

    public function setEmitChangetypeForAdds(bool $emitChangetypeForAdds): self
    {
        $this->emitChangetypeForAdds = $emitChangetypeForAdds;

        return $this;
    }
}
