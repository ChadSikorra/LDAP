<?php

declare(strict_types=1);

namespace Tests\Support\FreeDSx\Ldap;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Ldif\Loader\FileLdifLoader;
use FreeDSx\Ldap\Ldif\Output\FileLdifOutput;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\JsonFileStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\MysqlStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqliteStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\LdapImporter;
use FreeDSx\Ldap\ServerOptions;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\FileFlagConfigReloader;
use PDO;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

final class LdapServerCommand extends Command
{
    use ConsoleOptionsTrait;

    private const SSL_KEY = __DIR__ . '/../resources/cert/slapd.key';

    private const SSL_CERT = __DIR__ . '/../resources/cert/slapd.crt';

    private const VALID_STORAGE = ['memory', 'json', 'sqlite', 'mysql'];

    protected function configure(): void
    {
        $this
            ->setName('ldap-server')
            ->setDescription('Run the test LDAP server')
            ->addOption(
                'transport',
                null,
                InputOption::VALUE_REQUIRED,
                'Transport type (tcp, ssl, unix)',
                'tcp',
            )
            ->addOption(
                'port',
                null,
                InputOption::VALUE_REQUIRED,
                'Port to listen on',
                '10389',
            )
            ->addOption(
                'storage',
                null,
                InputOption::VALUE_REQUIRED,
                'Storage adapter (' . implode(', ', self::VALID_STORAGE) . ')',
                'memory',
            )
            ->addOption(
                'entries',
                null,
                InputOption::VALUE_REQUIRED,
                'Number of extra entries to seed (used to test paging)',
                '0',
            )
            ->addOption(
                'sasl',
                null,
                InputOption::VALUE_NONE,
                'Enable SASL mechanisms with plaintext-password storage',
            )
            ->addOption(
                'allow-anonymous',
                null,
                InputOption::VALUE_NONE,
                'Allow anonymous bind',
            )
            ->addOption(
                'seed',
                null,
                InputOption::VALUE_REQUIRED,
                'Load directory data from an LDIF file via LdapServer::seed() instead of the built-in entries',
                '',
            )
            ->addOption(
                'changes',
                null,
                InputOption::VALUE_REQUIRED,
                'After seeding, replay an LDIF changelog file via LdapServer::applyChanges()',
                '',
            )
            ->addOption(
                'dump',
                null,
                InputOption::VALUE_REQUIRED,
                'After seeding/applying changes, dump the directory to an LDIF file via LdapServer::dump()',
                '',
            )
            ->addOption(
                'reload-flag-file',
                null,
                InputOption::VALUE_REQUIRED,
                'On SIGHUP, re-read this file and enable anonymous bind when it contains "allow-anonymous"',
                '',
            );
    }

    protected function execute(
        InputInterface $input,
        OutputInterface $output,
    ): int {
        $io = new SymfonyStyle($input, $output);
        $transport = $this->getStringOption($input, 'transport');
        $port = (int) $this->getStringOption($input, 'port');
        $storageType = $this->getStringOption($input, 'storage');
        $entryCount = (int) $this->getStringOption($input, 'entries');
        $sasl = $input->getOption('sasl') === true;
        $allowAnonymous = $input->getOption('allow-anonymous') === true;
        $seedFile = $this->getStringOption($input, 'seed');
        $changesFile = $this->getStringOption($input, 'changes');
        $dumpFile = $this->getStringOption($input, 'dump');
        $reloadFlagFile = $this->getStringOption($input, 'reload-flag-file');
        $useSsl = false;

        if (!in_array($storageType, self::VALID_STORAGE, true)) {
            $io->error("Invalid --storage value: {$storageType}. Expected one of: " . implode(', ', self::VALID_STORAGE) . '.');

            return Command::FAILURE;
        }

        if ($transport === 'ssl') {
            $transport = 'tcp';
            $useSsl = true;
        }

        $entries = $sasl ? $this->buildSaslEntries() : $this->buildDefaultEntries();

        for ($i = 1; $i <= $entryCount; $i++) {
            $entries[] = Entry::fromArray(
                "cn=entry-{$i},dc=foo,dc=bar",
                [
                    'cn' => "entry-{$i}",
                    'objectClass' => 'inetOrgPerson',
                    'sn' => 'Entry',
                    'foo' => (string) $i,
                ],
            );
        }

        $storage = $this->createStorage($storageType);

        $options = (new ServerOptions())
            ->setPort($port)
            ->setTransport($transport)
            ->setUnixSocket(sys_get_temp_dir() . '/ldap.socket')
            ->setSslCert(self::SSL_CERT)
            ->setSslCertKey(self::SSL_KEY)
            ->setUseSsl($useSsl)
            ->setAllowAnonymous($allowAnonymous)
            ->setSocketAcceptTimeout(0.1)
            ->setOnServerReady(fn() => fwrite(STDOUT, 'server starting...' . PHP_EOL));

        if ($reloadFlagFile !== '') {
            $options->setConfigReloader(new FileFlagConfigReloader($reloadFlagFile));
        }

        $server = new LdapServer($options);

        if ($sasl) {
            $options->setSaslMechanisms(
                ServerOptions::SASL_PLAIN,
                ServerOptions::SASL_CRAM_MD5,
                ServerOptions::SASL_SCRAM_SHA_256,
            );
        }

        $server->useStorage($storage);

        if ($seedFile !== '') {
            $server->seed(new FileLdifLoader($seedFile));
        } else {
            (new LdapImporter($storage))->importEntries($entries);
        }

        if ($changesFile !== '') {
            $server->applyChanges(new FileLdifLoader($changesFile));
        }

        if ($dumpFile !== '') {
            $server->dump(new FileLdifOutput($dumpFile));
        }

        $server->run();

        return Command::SUCCESS;
    }

    private function createStorage(string $storageType): EntryStorageInterface
    {
        if ($storageType === 'json') {
            $filePath = sys_get_temp_dir() . '/ldap_test_server.json';

            if (file_exists($filePath)) {
                unlink($filePath);
            }

            return JsonFileStorage::forPcntl($filePath);
        }

        if ($storageType === 'sqlite') {
            $dbPath = sys_get_temp_dir() . '/ldap_test_server.sqlite';

            foreach ([$dbPath, $dbPath . '-wal', $dbPath . '-shm'] as $path) {
                if (file_exists($path)) {
                    unlink($path);
                }
            }

            return SqliteStorage::forPcntl($dbPath);
        }

        if ($storageType === 'mysql') {
            $dsn = getenv('MYSQL_DSN') ?: 'mysql:host=127.0.0.1;port=3306;dbname=freedsx';
            $user = getenv('MYSQL_USER') ?: 'root';
            $password = getenv('MYSQL_PASSWORD') ?: 'root';

            $cleanup = new PDO(
                $dsn,
                $user,
                $password,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
            );
            $cleanup->exec('DROP TABLE IF EXISTS entry_attribute_values');
            $cleanup->exec('DROP TABLE IF EXISTS entries');
            unset($cleanup);

            return MysqlStorage::forPcntl($dsn, $user, $password);
        }

        return new InMemoryStorage();
    }

    /**
     * @return list<Entry>
     */
    private function buildDefaultEntries(): array
    {
        $passwordHash = '{SHA}' . base64_encode(sha1('12345', true));

        return [
            Entry::fromArray(
                'dc=foo,dc=bar',
                [
                    'dc' => 'foo',
                    'objectClass' => 'domain',
                ],
            ),
            Entry::fromArray(
                'cn=user,dc=foo,dc=bar',
                [
                    'cn' => 'user',
                    'sn' => 'User',
                    'objectClass' => 'inetOrgPerson',
                    'userPassword' => $passwordHash,
                ],
            ),
        ];
    }

    /**
     * @return list<Entry>
     */
    private function buildSaslEntries(): array
    {
        return [
            Entry::fromArray(
                'dc=foo,dc=bar',
                [
                    'dc' => 'foo',
                    'objectClass' => 'domain',
                ],
            ),
            Entry::fromArray(
                'cn=user,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'user',
                    'uid' => 'user',
                    'userPassword' => '12345',
                ],
            ),
            Entry::fromArray(
                'cn=other,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'other',
                    'uid' => 'other',
                    'userPassword' => 'secret',
                ],
            ),
        ];
    }
}
