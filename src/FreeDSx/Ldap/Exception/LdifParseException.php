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

namespace FreeDSx\Ldap\Exception;

use Exception;

/**
 * Represents an issue encountered while parsing LDIF.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdifParseException extends Exception
{
    public function __construct(
        string $message,
        private readonly int $lineNumber = 0,
        private readonly ?string $sourceLine = null,
    ) {
        parent::__construct(
            $lineNumber > 0
                ? sprintf('%s (LDIF line %d).', $message, $lineNumber)
                : $message,
        );
    }

    /**
     * The 1-based LDIF line where parsing failed; 0 when not applicable.
     */
    public function getLineNumber(): int
    {
        return $this->lineNumber;
    }

    /**
     * The raw LDIF line that triggered the error, if known.
     */
    public function getSourceLine(): ?string
    {
        return $this->sourceLine;
    }
}
