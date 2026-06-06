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

namespace FreeDSx\Ldap\Ldif\Output;

use Stringable;

/**
 * Accumulates LDIF chunks into an in-memory string.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class StringLdifOutput implements LdifOutputInterface, Stringable
{
    private string $ldif = '';

    /**
     * @param iterable<string> $chunks
     */
    public function write(iterable $chunks): void
    {
        foreach ($chunks as $chunk) {
            $this->ldif .= $chunk;
        }
    }

    public function getLdif(): string
    {
        return $this->ldif;
    }

    public function __toString(): string
    {
        return $this->ldif;
    }
}
