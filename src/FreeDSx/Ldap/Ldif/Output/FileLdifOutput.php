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

use FreeDSx\Ldap\Exception\RuntimeException;

use function dirname;
use function fclose;
use function fopen;
use function fwrite;
use function is_dir;
use function is_writable;
use function sprintf;

/**
 * Streams LDIF chunks to a file path.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class FileLdifOutput implements LdifOutputInterface
{
    public function __construct(private string $path) {}

    /**
     * @param iterable<string> $chunks
     * @throws RuntimeException when the file cannot be opened or written
     */
    public function write(iterable $chunks): void
    {
        $dir = dirname($this->path);

        if (!is_dir($dir) || !is_writable($dir)) {
            throw new RuntimeException(sprintf(
                'Unable to open "%s" for writing.',
                $this->path,
            ));
        }

        $handle = fopen($this->path, 'w');

        if ($handle === false) {
            throw new RuntimeException(sprintf(
                'Unable to open "%s" for writing.',
                $this->path,
            ));
        }

        try {
            foreach ($chunks as $chunk) {
                fwrite(
                    $handle,
                    $chunk,
                );
            }
        } finally {
            fclose($handle);
        }
    }
}
