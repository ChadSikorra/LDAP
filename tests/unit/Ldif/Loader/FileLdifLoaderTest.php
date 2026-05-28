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

namespace Tests\Unit\FreeDSx\Ldap\Ldif\Loader;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Ldif\Loader\FileLdifLoader;
use PHPUnit\Framework\TestCase;

final class FileLdifLoaderTest extends TestCase
{
    public function test_it_loads_the_file_contents(): void
    {
        $path = tempnam(
            sys_get_temp_dir(),
            'ldif',
        );
        self::assertIsString($path);
        file_put_contents(
            $path,
            "dn: dc=x\ndc: x\n",
        );

        try {
            self::assertSame(
                "dn: dc=x\ndc: x\n",
                (new FileLdifLoader($path))->load(),
            );
        } finally {
            unlink($path);
        }
    }

    public function test_it_throws_for_a_missing_file(): void
    {
        $this->expectException(RuntimeException::class);

        (new FileLdifLoader('/does/not/exist/seed.ldif'))->load();
    }
}
