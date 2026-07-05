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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SchemaFile;
use PHPUnit\Framework\TestCase;

final class SchemaFileTest extends TestCase
{
    public function test_split_returns_trimmed_non_empty_statements(): void
    {
        $statements = SchemaFile::split(
            "CREATE TABLE a (x TEXT);\n\nCREATE INDEX i ON a (x);\n\nINSERT OR IGNORE INTO a VALUES ('y');\n",
        );

        self::assertSame(
            [
                'CREATE TABLE a (x TEXT)',
                'CREATE INDEX i ON a (x)',
                "INSERT OR IGNORE INTO a VALUES ('y')",
            ],
            $statements,
        );
    }

    public function test_split_of_an_empty_script_is_empty(): void
    {
        self::assertSame(
            [],
            SchemaFile::split("\n  \n"),
        );
    }

    public function test_statements_reads_and_splits_the_file(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'schema') ?: throw new RuntimeException('tempnam failed');
        file_put_contents(
            $path,
            "CREATE TABLE a (x TEXT);\nCREATE TABLE b (y TEXT);\n",
        );

        try {
            self::assertSame(
                [
                    'CREATE TABLE a (x TEXT)',
                    'CREATE TABLE b (y TEXT)',
                ],
                (new SchemaFile($path))->statements(),
            );
        } finally {
            unlink($path);
        }
    }

    public function test_reading_a_missing_file_throws(): void
    {
        $this->expectException(RuntimeException::class);

        (new SchemaFile('/does/not/exist.sql'))->sql();
    }
}
