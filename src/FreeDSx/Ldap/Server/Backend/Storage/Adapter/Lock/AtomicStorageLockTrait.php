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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock;

use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use Throwable;

/**
 * Shared atomic read-mutate-publish flow: serialize via the consumer's lock primitive, then stage + rename.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait AtomicStorageLockTrait
{
    public function __construct(private readonly string $filePath) {}

    final public function withLock(
        callable $mutation,
        ?callable $afterCommit = null,
    ): void {
        $this->withExclusive(function () use ($mutation, $afterCommit): void {
            $newContents = $mutation($this->readCurrentContents());
            $this->publishAtomically($newContents);

            if ($afterCommit !== null) {
                $afterCommit();
            }
        });
    }

    final public function withExclusive(callable $callback): void
    {
        $this->acquireLock();

        try {
            $callback();
        } finally {
            $this->releaseLock();
        }
    }

    /**
     * Acquire the exclusive lock, or bump the re-entrancy depth when already held by this execution context.
     */
    abstract private function acquireLock(): void;

    /**
     * Drop the re-entrancy depth, releasing the underlying lock only when the outermost holder exits.
     */
    abstract private function releaseLock(): void;

    abstract private function readCurrentContents(): string;

    abstract private function writeContentsToTemp(
        string $tmpPath,
        string $contents,
    ): int;

    private function publishAtomically(string $contents): void
    {
        $tmpPath = tempnam(
            dirname($this->filePath),
            'ldap-storage-',
        );

        if ($tmpPath === false) {
            throw new StorageIoException('Unable to stage the storage update.');
        }

        try {
            $bytesWritten = $this->writeContentsToTemp(
                $tmpPath,
                $contents,
            );

            if ($bytesWritten !== strlen($contents)) {
                throw new StorageIoException('Unable to stage the storage update.');
            }

            if (!rename($tmpPath, $this->filePath)) {
                throw new StorageIoException('Unable to publish the storage update.');
            }
        } catch (Throwable $e) {
            if (file_exists($tmpPath)) {
                unlink($tmpPath);
            }

            throw $e;
        }
    }
}
