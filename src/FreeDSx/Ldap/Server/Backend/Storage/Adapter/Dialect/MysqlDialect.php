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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\MysqlFilterTranslator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;

/**
 * MySQL/MariaDB SQL for PdoStorage; requires MySQL 8.0+ or MariaDB 10.6+.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class MysqlDialect implements PdoDialectInterface
{
    use PdoDialectTrait;
    use PdoJournalDialectTrait;
    use PdoSchemaTrait;

    public function createFilterTranslator(?SubstringIndexInterface $substringIndex): FilterTranslatorInterface
    {
        return new MysqlFilterTranslator($substringIndex);
    }

    /**
     * @todo Replace VALUES() with row alias syntax once MariaDB supports it.
     */
    public function queryUpsert(): string
    {
        return <<<SQL
            INSERT INTO entries (lc_dn, dn, lc_parent_dn, attributes)
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                dn = VALUES(dn),
                lc_parent_dn = VALUES(lc_parent_dn),
                attributes = VALUES(attributes)
        SQL;
    }

    public function maxDnLength(): int
    {
        return 768;
    }

    protected function schemaName(): string
    {
        return 'mysql';
    }
}
