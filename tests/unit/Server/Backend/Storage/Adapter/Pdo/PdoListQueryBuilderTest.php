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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo;

use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\MysqlDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoListQueryBuilder;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterResult;
use PHPUnit\Framework\TestCase;

final class PdoListQueryBuilderTest extends TestCase
{
    /**
     * @return array{0: string, 1: list<string>}
     */
    private function rootQuery(
        PdoListQueryBuilder $builder,
        ?SqlFilterResult $filter,
        SortKey ...$sortKeys,
    ): array {
        $query = $builder->build(
            '',
            true,
            $filter,
            null,
            $sortKeys,
        );

        return [$query->sql, $query->params];
    }

    public function test_no_sort_keys_appends_no_order_by(): void
    {
        [$sql, $params] = $this->rootQuery(
            new PdoListQueryBuilder(new SqliteDialect()),
            null,
        );

        self::assertStringNotContainsString('ORDER BY', $sql);
        self::assertSame([], $params);
    }

    public function test_sqlite_ascending_orders_nulls_last_with_one_param(): void
    {
        [$sql, $params] = $this->rootQuery(
            new PdoListQueryBuilder(new SqliteDialect()),
            null,
            SortKey::ascending('CN'),
        );

        self::assertStringContainsString('ORDER BY', $sql);
        self::assertStringContainsString('ASC NULLS LAST', $sql);
        self::assertSame(['cn'], $params);
    }

    public function test_sqlite_descending_orders_nulls_first_with_one_param(): void
    {
        [$sql, $params] = $this->rootQuery(
            new PdoListQueryBuilder(new SqliteDialect()),
            null,
            SortKey::descending('cn'),
        );

        self::assertStringContainsString('DESC NULLS FIRST', $sql);
        self::assertSame(['cn'], $params);
    }

    public function test_mysql_ascending_emulates_nulls_last_with_two_params(): void
    {
        [$sql, $params] = $this->rootQuery(
            new PdoListQueryBuilder(new MysqlDialect()),
            null,
            SortKey::ascending('cn'),
        );

        self::assertStringContainsString('IS NULL ASC', $sql);
        self::assertSame(['cn', 'cn'], $params);
    }

    public function test_mysql_descending_emulates_nulls_first_with_two_params(): void
    {
        [$sql, $params] = $this->rootQuery(
            new PdoListQueryBuilder(new MysqlDialect()),
            null,
            SortKey::descending('cn'),
        );

        self::assertStringContainsString('IS NULL DESC', $sql);
        self::assertSame(['cn', 'cn'], $params);
    }

    public function test_mysql_multi_key_preserves_param_order(): void
    {
        [, $params] = $this->rootQuery(
            new PdoListQueryBuilder(new MysqlDialect()),
            null,
            SortKey::ascending('sn'),
            SortKey::descending('cn'),
        );

        self::assertSame(
            ['sn', 'sn', 'cn', 'cn'],
            $params,
        );
    }

    public function test_filter_params_precede_sort_params(): void
    {
        [, $params] = $this->rootQuery(
            new PdoListQueryBuilder(new SqliteDialect()),
            new SqlFilterResult('eav.value_lower = ?', ['smith']),
            SortKey::ascending('sn'),
        );

        self::assertSame(
            ['smith', 'sn'],
            $params,
        );
    }
}
