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

namespace FreeDSx\Ldap\Ldif\Loader;

use FreeDSx\Ldap\Exception\RuntimeException;
use Generator;

use function fclose;
use function feof;
use function fgets;
use function fopen;
use function is_file;
use function is_readable;
use function rtrim;
use function sprintf;

/**
 * Streams LDIF lines from a file.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class FileLdifLoader implements LdifLoaderInterface
{
    public function __construct(private string $file) {}

    /**
     * @return Generator<string>
     * @throws RuntimeException when the file is missing or unreadable
     */
    public function load(): Generator
    {
        if (!is_file($this->file) || !is_readable($this->file)) {
            throw new RuntimeException(sprintf(
                'The LDIF file "%s" is missing or not readable.',
                $this->file,
            ));
        }

        $handle = fopen(
            $this->file,
            'r',
        );

        if ($handle === false) {
            throw new RuntimeException(sprintf(
                'Unable to read the LDIF file "%s".',
                $this->file,
            ));
        }

        try {
            while (!feof($handle)) {
                $line = fgets($handle);

                if ($line === false) {
                    break;
                }

                yield rtrim(
                    $line,
                    "\r\n",
                );
            }
        } finally {
            fclose($handle);
        }
    }
}
