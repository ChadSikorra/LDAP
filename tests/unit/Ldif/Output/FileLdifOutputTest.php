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

namespace Tests\Unit\FreeDSx\Ldap\Ldif\Output;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Ldif\Output\FileLdifOutput;
use PHPUnit\Framework\TestCase;

final class FileLdifOutputTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = (string) tempnam(sys_get_temp_dir(), 'ldif-output-test-');
    }

    protected function tearDown(): void
    {
        if (file_exists($this->path)) {
            unlink($this->path);
        }
    }

    public function test_it_writes_chunks_to_the_file_in_order(): void
    {
        (new FileLdifOutput($this->path))->write([
            "version: 1\n\n",
            "dn: cn=a,dc=x\n",
            "cn: a\n",
        ]);

        self::assertSame(
            "version: 1\n\ndn: cn=a,dc=x\ncn: a\n",
            (string) file_get_contents($this->path),
        );
    }

    public function test_it_consumes_a_generator(): void
    {
        $generator = (function (): iterable {
            yield "dn: cn=a,dc=x\n";
            yield "cn: a\n";
        })();

        (new FileLdifOutput($this->path))->write($generator);

        self::assertSame(
            "dn: cn=a,dc=x\ncn: a\n",
            (string) file_get_contents($this->path),
        );
    }

    public function test_it_truncates_an_existing_file(): void
    {
        file_put_contents(
            $this->path,
            'pre-existing content',
        );

        (new FileLdifOutput($this->path))->write(["dn: cn=fresh,dc=x\n"]);

        self::assertSame(
            "dn: cn=fresh,dc=x\n",
            (string) file_get_contents($this->path),
        );
    }

    public function test_it_throws_when_the_file_cannot_be_opened(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to open');

        (new FileLdifOutput('/nonexistent-dir/should-fail.ldif'))->write([]);
    }
}
