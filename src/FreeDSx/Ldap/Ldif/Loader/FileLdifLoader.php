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

use function file_get_contents;
use function is_file;
use function is_readable;

/**
 * Loads LDIF text from a file.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class FileLdifLoader implements LdifLoaderInterface
{
    public function __construct(private string $file) {}

    /**
     * @throws RuntimeException when the file is missing or unreadable
     */
    public function load(): string
    {
        if (!is_file($this->file) || !is_readable($this->file)) {
            throw new RuntimeException(sprintf(
                'The LDIF file "%s" is missing or not readable.',
                $this->file,
            ));
        }

        $ldif = file_get_contents($this->file);

        if ($ldif === false) {
            throw new RuntimeException(sprintf(
                'Unable to read the LDIF file "%s".',
                $this->file,
            ));
        }

        return $ldif;
    }
}
