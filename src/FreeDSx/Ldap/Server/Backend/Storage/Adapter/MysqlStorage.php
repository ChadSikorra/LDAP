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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\MysqlDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoStorageFactoryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoStorageFactoryTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\MysqlFilterTranslator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use PDO;
use SensitiveParameter;

/**
 * MySQL/MariaDB factory for PdoStorage; use forPcntl()/forSwoole() to select the runner. Requires MySQL 8.0+ or MariaDB 10.6+.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class MysqlStorage implements PdoStorageFactoryInterface
{
    use PdoStorageFactoryTrait;

    public function __construct(
        private readonly string $dsn,
        private readonly string $username,
        #[SensitiveParameter]
        private readonly string $password,
        private readonly bool $initializeSchema = true,
        private readonly ?SubstringIndexInterface $substringIndex = null,
    ) {}

    /**
     * @param list<string>|null $substringIndexedAttributes null uses the default indexed set, [] disables substring indexing
     */
    public static function forPcntl(
        string $dsn,
        string $username,
        #[SensitiveParameter]
        string $password,
        bool $initializeSchema = true,
        ?array $substringIndexedAttributes = null,
    ): PdoStorage {
        return (new self(
            $dsn,
            $username,
            $password,
            $initializeSchema,
            self::resolveSubstringIndex($substringIndexedAttributes),
        ))->createShared();
    }

    /**
     * @param list<string>|null $substringIndexedAttributes null uses the default indexed set, [] disables substring indexing
     */
    public static function forSwoole(
        string $dsn,
        string $username,
        #[SensitiveParameter]
        string $password,
        bool $initializeSchema = true,
        ?array $substringIndexedAttributes = null,
    ): PdoStorage {
        return (new self(
            $dsn,
            $username,
            $password,
            $initializeSchema,
            self::resolveSubstringIndex($substringIndexedAttributes),
        ))->createPerCoroutine();
    }

    /**
     * The MySQL schema as a runnable SQL script, to export or apply with your own migration tooling.
     */
    public static function schemaDdl(): string
    {
        return PdoStorage::schemaDdl(new MysqlDialect());
    }

    protected function dialect(): PdoDialectInterface
    {
        return new MysqlDialect();
    }

    protected function translator(): FilterTranslatorInterface
    {
        return new MysqlFilterTranslator();
    }

    protected function substringIndex(): ?SubstringIndexInterface
    {
        return $this->substringIndex;
    }

    protected function openConnection(PdoDialectInterface $dialect): PDO
    {
        if (!extension_loaded('pdo_mysql')) {
            throw new RuntimeException(
                'The "pdo_mysql" extension is required for the MySQL storage backend.',
            );
        }

        $pdo = new PDO(
            $this->dsn,
            $this->username,
            $this->password,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_EMULATE_PREPARES => false,
            ],
        );
        $pdo->exec("SET NAMES utf8mb4");
        $pdo->exec("SET time_zone = '+00:00'");

        if ($this->initializeSchema) {
            PdoStorage::initialize(
                $pdo,
                $dialect,
                $this->substringIndex,
            );
        }

        return $pdo;
    }
}
