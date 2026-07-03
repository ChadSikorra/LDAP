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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\FileLock;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use PHPUnit\Framework\TestCase;

final class FileLockTest extends TestCase
{
    private string $tempFile;

    protected function setUp(): void
    {
        $this->tempFile = sys_get_temp_dir() . '/ldap_test_filelock_' . uniqid() . '.dat';
    }

    protected function tearDown(): void
    {
        foreach ([$this->tempFile, $this->tempFile . '.lock', $this->tempFile . '.sidecar'] as $path) {
            if (file_exists($path)) {
                unlink($path);
            }
        }
    }

    public function test_reads_empty_string_when_main_file_does_not_exist(): void
    {
        $lock = new FileLock($this->tempFile);
        $observed = null;

        $lock->withLock(function (string $contents) use (&$observed): string {
            $observed = $contents;

            return 'initial';
        });

        self::assertSame(
            '',
            $observed,
        );
    }

    public function test_passes_existing_file_contents_to_mutation(): void
    {
        file_put_contents($this->tempFile, 'existing payload');
        $lock = new FileLock($this->tempFile);
        $observed = null;

        $lock->withLock(function (string $contents) use (&$observed): string {
            $observed = $contents;

            return $contents;
        });

        self::assertSame(
            'existing payload',
            $observed,
        );
    }

    public function test_publishes_mutation_result_to_main_file(): void
    {
        $lock = new FileLock($this->tempFile);

        $lock->withLock(fn(string $_): string => 'first');
        $lock->withLock(fn(string $contents): string => $contents . '|second');

        self::assertSame(
            'first|second',
            file_get_contents($this->tempFile),
        );
    }

    public function test_creates_sidecar_lock_file_alongside_main_file(): void
    {
        $lock = new FileLock($this->tempFile);
        $lock->withLock(fn(string $_): string => 'payload');

        self::assertFileExists($this->tempFile . '.lock');
    }

    public function test_main_file_is_never_left_empty_after_publish(): void
    {
        $lock = new FileLock($this->tempFile);

        $lock->withLock(fn(string $_): string => 'v1');
        self::assertSame(
            'v1',
            file_get_contents($this->tempFile),
        );

        $lock->withLock(fn(string $_): string => 'v2 (larger payload)');
        self::assertSame(
            'v2 (larger payload)',
            file_get_contents($this->tempFile),
        );
    }

    public function test_throws_storage_io_exception_when_lock_directory_is_unwritable(): void
    {
        $lock = new FileLock('/nonexistent-ldap-test-dir/storage.dat');

        self::expectException(StorageIoException::class);

        set_error_handler(static fn(): bool => true);

        try {
            $lock->withLock(fn(string $_): string => 'payload');
        } finally {
            restore_error_handler();
        }
    }

    public function test_releases_lock_and_rethrows_when_mutation_throws(): void
    {
        file_put_contents($this->tempFile, 'original');
        $lock = new FileLock($this->tempFile);

        try {
            $lock->withLock(function (string $_): string {
                throw new \RuntimeException('mutation failed');
            });
            self::fail('Expected exception was not thrown.');
        } catch (\RuntimeException $e) {
            self::assertSame(
                'mutation failed',
                $e->getMessage(),
            );
        }

        self::assertSame(
            'original',
            file_get_contents($this->tempFile),
        );

        $second = new FileLock($this->tempFile);
        $second->withLock(fn(string $contents): string => $contents . '|recovered');

        self::assertSame(
            'original|recovered',
            file_get_contents($this->tempFile),
        );
    }

    public function test_with_exclusive_runs_the_callback_under_the_lock(): void
    {
        $lock = new FileLock($this->tempFile);
        $ran = false;

        $lock->withExclusive(function () use (&$ran): void {
            $ran = true;
        });

        self::assertTrue($ran);
        self::assertFileExists($this->tempFile . '.lock');
    }

    public function test_with_exclusive_is_reentrant_and_does_not_deadlock(): void
    {
        $lock = new FileLock($this->tempFile);
        $depth = 0;

        // A nested acquire in the same process must not block on its own flock().
        $lock->withExclusive(function () use ($lock, &$depth): void {
            $lock->withExclusive(function () use (&$depth): void {
                $depth = 2;
            });
        });

        self::assertSame(
            2,
            $depth,
        );
    }

    public function test_a_journal_style_append_runs_within_a_write_without_deadlocking(): void
    {
        $lock = new FileLock($this->tempFile);
        $sidecar = $this->tempFile . '.sidecar';

        $lock->withLock(
            fn(string $_): string => 'entry-data',
            // Mirrors the journal flush: a nested exclusive write while the data lock is still held.
            function () use ($lock, $sidecar): void {
                $lock->withExclusive(function () use ($sidecar): void {
                    file_put_contents(
                        $sidecar,
                        'journal-record',
                    );
                });
            },
        );

        self::assertSame(
            'entry-data',
            file_get_contents($this->tempFile),
        );
        self::assertSame(
            'journal-record',
            file_get_contents($sidecar),
        );
    }

    public function test_after_commit_runs_after_the_data_is_published(): void
    {
        $lock = new FileLock($this->tempFile);
        $seenDuringAfterCommit = null;

        $lock->withLock(
            fn(string $_): string => 'published',
            function () use (&$seenDuringAfterCommit): void {
                $seenDuringAfterCommit = file_get_contents($this->tempFile);
            },
        );

        self::assertSame(
            'published',
            $seenDuringAfterCommit,
        );
    }

    public function test_after_commit_is_skipped_when_the_mutation_throws(): void
    {
        $lock = new FileLock($this->tempFile);
        $afterCommitRan = false;

        try {
            $lock->withLock(
                function (string $_): string {
                    throw new \RuntimeException('mutation failed');
                },
                function () use (&$afterCommitRan): void {
                    $afterCommitRan = true;
                },
            );
            self::fail('Expected exception was not thrown.');
        } catch (\RuntimeException) {
        }

        self::assertFalse($afterCommitRan);
    }

    public function test_reentrant_use_balances_the_depth_counter(): void
    {
        $lock = new FileLock($this->tempFile);

        $lock->withExclusive(function () use ($lock): void {
            $lock->withLock(fn(string $_): string => 'data');
        });

        $depth = new \ReflectionProperty(
            $lock,
            'depth',
        );

        // Back to zero means the underlying flock was released exactly once, at the outermost exit.
        self::assertSame(
            0,
            $depth->getValue($lock),
        );
    }
}
