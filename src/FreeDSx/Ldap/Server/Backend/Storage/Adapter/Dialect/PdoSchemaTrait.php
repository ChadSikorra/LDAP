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

use FreeDSx\Ldap\Resources;

/**
 * Loads a dialect's baseline schema from its shipped .sql resource file.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait PdoSchemaTrait
{
    public function schemaSql(): string
    {
        return $this->schemaFile()
            ->sql();
    }

    /**
     * @return list<string>
     */
    public function schemaStatements(): array
    {
        return $this->schemaFile()
            ->statements();
    }

    /**
     * The dialect's resource directory name under resources/schema.
     */
    abstract protected function schemaName(): string;

    private function schemaFile(): SchemaFile
    {
        return new SchemaFile(Resources::path(
            'schema/' . $this->schemaName() . '/baseline.sql',
        ));
    }
}
