<?php

declare(strict_types=1);

namespace Tests\Support\FreeDSx\Ldap;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\Rule\ControlRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Target\Target;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\JsonFileStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoStorageFactory;
use FreeDSx\Ldap\Server\Backend\Storage\LdapImporter;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\ServerOptions;
use PDO;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

final class LdapBackendStorageCommand extends Command
{
    use ConsoleOptionsTrait;

    protected function configure(): void
    {
        $this
            ->setName('ldap-backend-storage')
            ->setDescription('Run the test LDAP server with a pluggable storage backend')
            ->addOption(
                'transport',
                null,
                InputOption::VALUE_REQUIRED,
                'Transport type (tcp, unix)',
                'tcp',
            )
            ->addOption(
                'storage',
                null,
                InputOption::VALUE_REQUIRED,
                'Storage adapter (memory, json, sqlite, mysql)',
                'memory',
            )
            ->addOption(
                'runner',
                null,
                InputOption::VALUE_REQUIRED,
                'Server runner (pcntl, swoole)',
                'pcntl',
            )
            ->addOption(
                'port',
                null,
                InputOption::VALUE_REQUIRED,
                'Port to listen on',
                '10389',
            )
            ->addOption(
                'seed-entries',
                null,
                InputOption::VALUE_REQUIRED,
                'Number of additional seed entries to generate',
                '0',
            )
            ->addOption(
                'validation-mode',
                null,
                InputOption::VALUE_REQUIRED,
                'Schema validation mode (strict, lenient, off)',
                'strict',
            )
            ->addOption(
                'allow-relax',
                null,
                InputOption::VALUE_NONE,
                'Grant the Relax Rules control to authenticated identities',
            )
            ->addOption(
                'allow-proxy',
                null,
                InputOption::VALUE_NONE,
                'Grant cn=user the Proxied Authorization control for identities under ou=people',
            )
            ->addOption(
                'monitor',
                null,
                InputOption::VALUE_NONE,
                'Enable the cn=monitor entry',
            )
            ->addOption(
                'max-search-lookthrough',
                null,
                InputOption::VALUE_REQUIRED,
                'Maximum entries examined per search before adminLimitExceeded (0 = no limit)',
                '0',
            );
    }

    protected function execute(
        InputInterface $input,
        OutputInterface $output,
    ): int {
        $io = new SymfonyStyle($input, $output);

        $transport = $this->getStringOption($input, 'transport');
        $storage = $this->getStringOption($input, 'storage');
        $runner = $this->getStringOption($input, 'runner');
        $port = (int) $this->getStringOption($input, 'port');
        $seedEntries = (int) $this->getStringOption($input, 'seed-entries');

        if (!in_array($storage, ['memory', 'json', 'sqlite', 'mysql'], true)) {
            $io->error("Invalid --storage value: {$storage}. Expected one of: memory, json, sqlite, mysql.");

            return Command::FAILURE;
        }

        if (!in_array($runner, ['pcntl', 'swoole'], true)) {
            $io->error("Invalid --runner value: {$runner}. Expected one of: pcntl, swoole.");

            return Command::FAILURE;
        }

        if ($seedEntries < 0) {
            $io->error("Invalid --seed-entries value: {$seedEntries}. Must be zero or greater.");

            return Command::FAILURE;
        }

        $validationMode = match ($this->getStringOption($input, 'validation-mode')) {
            'strict' => SchemaValidationMode::Strict,
            'lenient' => SchemaValidationMode::Lenient,
            'off' => SchemaValidationMode::Off,
            default => null,
        };

        if ($validationMode === null) {
            $io->error('Invalid --validation-mode value. Expected one of: strict, lenient, off.');

            return Command::FAILURE;
        }

        $passwordHash = '{SHA}' . base64_encode(sha1('12345', true));

        $entries = [
            new Entry(
                new Dn('dc=foo,dc=bar'),
                new Attribute('dc', 'foo'),
                new Attribute('objectClass', 'domain'),
            ),
            new Entry(
                new Dn('cn=user,dc=foo,dc=bar'),
                new Attribute('cn', 'user'),
                new Attribute('sn', 'Admin'),
                new Attribute('objectClass', 'inetOrgPerson'),
                new Attribute('userPassword', $passwordHash),
            ),
            new Entry(
                new Dn('ou=people,dc=foo,dc=bar'),
                new Attribute('ou', 'people'),
                new Attribute('objectClass', 'organizationalUnit'),
            ),
            new Entry(
                new Dn('cn=alice,ou=people,dc=foo,dc=bar'),
                new Attribute('cn', 'alice'),
                new Attribute('objectClass', 'inetOrgPerson', 'extensibleObject'),
                new Attribute('sn', 'Smith'),
                new Attribute('mail', 'alice@foo.bar'),
                new Attribute('uidNumber', '99'),
            ),
            new Entry(
                new Dn('cn=nosn,dc=foo,dc=bar'),
                new Attribute('cn', 'nosn'),
                new Attribute('objectClass', 'groupOfNames'),
                new Attribute('member', 'cn=user,dc=foo,dc=bar'),
            ),
        ];

        for ($i = 1; $i <= $seedEntries; $i++) {
            $entries[] = new Entry(
                new Dn("cn=seed-{$i},ou=people,dc=foo,dc=bar"),
                new Attribute('cn', "seed-{$i}"),
                new Attribute('objectClass', 'inetOrgPerson', 'extensibleObject'),
                new Attribute('sn', 'Seeded'),
                new Attribute('mail', "seed-{$i}@foo.bar"),
                new Attribute('uidNumber', (string) (1000 + $i)),
            );
        }

        $serverOptions = (new ServerOptions())
            ->setPort($port)
            ->setTransport($transport)
            ->setSocketAcceptTimeout(0.1)
            ->setSchemaValidationMode($validationMode)
            ->setMonitorEnabled((bool) $input->getOption('monitor'))
            ->setMaxSearchLookthrough((int) $this->getStringOption($input, 'max-search-lookthrough'))
            ->setOnServerReady(fn() => fwrite(STDOUT, 'server starting...' . PHP_EOL));

        if ($input->getOption('allow-relax')) {
            $serverOptions->setAclRules(
                (new AclRules())
                    ->withOperationRules(OperationRule::allow(Subject::authenticated()))
                    ->withControlRules(ControlRule::allow(
                        Subject::authenticated(),
                        Target::any(),
                        Control::OID_RELAX_RULES,
                    )),
            );
        }

        if ($input->getOption('allow-proxy')) {
            $serverOptions->setAclRules(
                (new AclRules())
                    ->withOperationRules(OperationRule::allow(Subject::authenticated()))
                    ->withControlRules(ControlRule::allow(
                        Subject::dn('cn=user,dc=foo,dc=bar'),
                        Target::subtree('ou=people,dc=foo,dc=bar'),
                        Control::OID_PROXY_AUTHORIZATION,
                    )),
            );
        }

        $server = new LdapServer($serverOptions);

        if ($storage === 'memory') {
            $server->getOptions()->setStorage(new InMemoryStorage($entries));
        } elseif ($storage === 'json') {
            $filePath = sys_get_temp_dir() . '/ldap_test_backend_storage.json';

            if (file_exists($filePath)) {
                unlink($filePath);
            }

            $adapter = $runner === 'swoole'
                ? JsonFileStorage::forSwoole($filePath)
                : JsonFileStorage::forPcntl($filePath);

            $importer = new LdapImporter($adapter);

            if ($runner === 'swoole') {
                \Swoole\Coroutine\run(fn() => $importer->importEntries($entries));
            } else {
                $importer->importEntries($entries);
            }

            $server->getOptions()->setStorage($adapter);
        } elseif ($storage === 'sqlite') {
            $dbPath = sys_get_temp_dir() . '/ldap_test_backend_storage.sqlite';

            foreach ([$dbPath, $dbPath . '-wal', $dbPath . '-shm'] as $path) {
                if (file_exists($path)) {
                    unlink($path);
                }
            }

            $adapter = $runner === 'swoole'
                ? PdoStorageFactory::forSwoole(PdoConfig::forSqlite($dbPath))
                : PdoStorageFactory::forPcntl(PdoConfig::forSqlite($dbPath));

            $importer = new LdapImporter($adapter);

            if ($runner === 'swoole') {
                \Swoole\Coroutine\run(fn() => $importer->importEntries($entries));
            } else {
                $importer->importEntries($entries);
            }

            $server->getOptions()->setStorage($adapter);
        } else {
            $dsn = getenv('MYSQL_DSN') ?: 'mysql:host=127.0.0.1;port=3306;dbname=freedsx';
            $user = getenv('MYSQL_USER') ?: 'root';
            $password = getenv('MYSQL_PASSWORD') ?: 'root';

            $cleanup = new PDO(
                $dsn,
                $user,
                $password,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
            );
            $cleanup->exec('DROP TABLE IF EXISTS entry_attribute_trigrams');
            $cleanup->exec('DROP TABLE IF EXISTS entry_attribute_values');
            $cleanup->exec('DROP TABLE IF EXISTS entries');
            unset($cleanup);

            $adapter = $runner === 'swoole'
                ? PdoStorageFactory::forSwoole(PdoConfig::forMysql($dsn, $user, $password))
                : PdoStorageFactory::forPcntl(PdoConfig::forMysql($dsn, $user, $password));

            $importer = new LdapImporter($adapter);

            if ($runner === 'swoole') {
                \Swoole\Coroutine\run(fn() => $importer->importEntries($entries));
            } else {
                $importer->importEntries($entries);
            }

            $server->getOptions()->setStorage($adapter);
        }

        if ($runner === 'swoole') {
            $server->getOptions()->setUseSwooleRunner(true);
        }

        $server->run();

        return Command::SUCCESS;
    }
}
