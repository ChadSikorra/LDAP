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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\MysqlStorage;
use PHPUnit\Framework\TestCase;

final class MysqlStorageTest extends TestCase
{
    public function test_schema_ddl_exports_the_mysql_baseline(): void
    {
        $ddl = MysqlStorage::schemaDdl();

        self::assertStringContainsString(
            'CREATE TABLE IF NOT EXISTS entries',
            $ddl,
        );
        self::assertStringContainsString(
            'ENGINE=InnoDB',
            $ddl,
        );
    }
}
