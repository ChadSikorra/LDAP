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
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;

/**
 * Swoole coroutine lock: serializes writes on a Channel(1) mutex and publishes updates atomically via rename().
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class CoroutineLock implements StorageLockInterface
{
    use AtomicStorageLockTrait;

    private const DEPTH_KEY = '__freedsx_storage_lock_depth';

    /**
     * @var Channel<mixed>|null
     */
    private ?Channel $mutex = null;

    private function acquireLock(): void
    {
        // Depth is tracked per coroutine, not per instance: coroutines share one lock.
        $depth = $this->currentDepth();
        if ($depth === 0) {
            $this->getOrCreateMutex()->pop();
        }

        $this->setCurrentDepth($depth + 1);
    }

    private function releaseLock(): void
    {
        $depth = $this->currentDepth();
        if ($depth === 0) {
            return;
        }

        $this->setCurrentDepth($depth - 1);

        if ($depth === 1) {
            $this->mutex?->push(true);
        }
    }

    private function currentDepth(): int
    {
        $context = Coroutine::getContext();
        if ($context === null) {
            return 0;
        }

        $depth = $context[self::DEPTH_KEY] ?? 0;

        return is_int($depth) ? $depth : 0;
    }

    private function setCurrentDepth(int $depth): void
    {
        $context = Coroutine::getContext();
        if ($context === null) {
            return;
        }

        $context[self::DEPTH_KEY] = $depth;
    }

    private function readCurrentContents(): string
    {
        $contents = Coroutine\System::readFile($this->filePath);

        return $contents !== false ? $contents : '';
    }

    private function writeContentsToTemp(
        string $tmpPath,
        string $contents,
    ): int {
        $bytesWritten = Coroutine\System::writeFile($tmpPath, $contents);

        if ($bytesWritten === false) {
            throw new StorageIoException('Unable to stage the storage update.');
        }

        return $bytesWritten;
    }

    /**
     * @return Channel<mixed>
     */
    private function getOrCreateMutex(): Channel
    {
        if ($this->mutex === null) {
            $this->mutex = self::createMutex();
        }

        return $this->mutex;
    }

    /**
     * @return Channel<mixed>
     */
    private static function createMutex(): Channel
    {
        $mutex = new Channel(1);
        $mutex->push(true);

        return $mutex;
    }
}
