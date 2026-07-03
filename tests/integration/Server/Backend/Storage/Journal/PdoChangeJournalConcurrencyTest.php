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

namespace Tests\Integration\FreeDSx\Ldap\Server\Backend\Storage\Journal;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoTransactor;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\PdoChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use PDO;
use PHPUnit\Framework\TestCase;
use Throwable;

final class PdoChangeJournalConcurrencyTest extends TestCase
{
    private const WORKERS = 8;

    private const WRITES_PER_WORKER = 25;

    private string $dbPath = '';

    protected function setUp(): void
    {
        if (!function_exists('pcntl_fork')) {
            $this->markTestSkipped('The journal concurrency proof requires the pcntl extension.');
        }

        $path = tempnam(sys_get_temp_dir(), 'journal-concurrency-');
        self::assertIsString($path);
        $this->dbPath = $path;

        // Create the schema once, up front, then drop the connection before forking so no handle is inherited.
        $pdo = $this->connect();
        PdoStorage::initialize($pdo, new SqliteDialect());
        unset($pdo);
    }

    protected function tearDown(): void
    {
        // setUp() may skip (Windows / no pcntl) before $dbPath is assigned, so there is nothing to clean.
        if ($this->dbPath === '') {
            return;
        }

        foreach ([$this->dbPath, $this->dbPath . '-wal', $this->dbPath . '-shm'] as $path) {
            if (is_file($path)) {
                @unlink($path);
            }
        }
    }

    public function test_concurrent_forked_writers_allocate_a_gap_free_collision_free_seq_run(): void
    {
        $pids = [];
        for ($worker = 0; $worker < self::WORKERS; $worker++) {
            $pid = pcntl_fork();
            self::assertNotSame(
                -1,
                $pid,
                'pcntl_fork failed',
            );

            if ($pid === 0) {
                exit($this->runWorker());
            }

            $pids[] = $pid;
        }

        $failed = 0;
        foreach ($pids as $pid) {
            $status = 0;
            pcntl_waitpid($pid, $status);
            if (!is_int($status) || !pcntl_wifexited($status) || pcntl_wexitstatus($status) !== 0) {
                $failed++;
            }
        }

        self::assertSame(
            0,
            $failed,
            'every forked writer committed its changes without error',
        );
        self::assertSame(
            range(1, self::WORKERS * self::WRITES_PER_WORKER),
            $this->readSeqs(),
        );
    }

    /**
     * Runs in a forked child on its own connection; returns the process exit code.
     */
    private function runWorker(): int
    {
        try {
            $journal = $this->makeJournal();
            for ($i = 0; $i < self::WRITES_PER_WORKER; $i++) {
                $journal->append(new PendingChange(
                    changeType: ChangeType::Add,
                    dn: new Dn(sprintf('cn=%d-%d,dc=example,dc=com', getmypid(), $i)),
                    entryUuid: '11111111-1111-4111-8111-111111111111',
                    authzId: AuthzId::anonymous(),
                ));
            }

            return 0;
        } catch (Throwable) {
            return 1;
        }
    }

    private function makeJournal(): PdoChangeJournal
    {
        $dialect = new SqliteDialect();

        return new PdoChangeJournal(
            new PdoTransactor(
                new SharedPdoConnectionProvider($this->connect()),
                $dialect,
            ),
            $dialect,
            new ReplicaId('node'),
        );
    }

    private function connect(): PDO
    {
        $pdo = new PDO('sqlite:' . $this->dbPath);
        $pdo->setAttribute(
            PDO::ATTR_ERRMODE,
            PDO::ERRMODE_EXCEPTION,
        );
        // WAL + a generous busy timeout: concurrent BEGIN IMMEDIATE writers wait for the lock instead of erroring.
        $pdo->exec('PRAGMA journal_mode=WAL');
        $pdo->exec('PRAGMA busy_timeout=10000');

        return $pdo;
    }

    /**
     * @return list<int>
     */
    private function readSeqs(): array
    {
        $stmt = $this->connect()
            ->query('SELECT seq FROM ldap_change_journal ORDER BY seq ASC');
        $rows = $stmt === false
            ? []
            : $stmt->fetchAll(PDO::FETCH_COLUMN);

        return array_values(array_map(
            static fn(mixed $value): int => is_numeric($value) ? (int) $value : 0,
            $rows,
        ));
    }
}
