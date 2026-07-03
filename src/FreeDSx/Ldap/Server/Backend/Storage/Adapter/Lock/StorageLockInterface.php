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

/**
 * Defines the strategy for atomically reading, mutating, and writing data.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface StorageLockInterface
{
    /**
     * Lock exclusively, hand the raw contents to $mutation, persist its return value, run $afterCommit while
     * still holding the lock, then release. $afterCommit sees the freshly committed data (e.g. journal flush).
     *
     * @param callable(string): string $mutation
     * @param ?callable(): void $afterCommit
     */
    public function withLock(
        callable $mutation,
        ?callable $afterCommit = null,
    ): void;

    /**
     * Run $callback under the exclusive lock without any data read/publish.
     *
     * @param callable(): void $callback
     */
    public function withExclusive(callable $callback): void;
}
