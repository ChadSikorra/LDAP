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

namespace FreeDSx\Ldap\Server\ServerRunner;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\ServerProtocolFactory;
use FreeDSx\Socket\Socket;
use FreeDSx\Socket\SocketServer;
use Psr\Log\LoggerInterface;
use Swoole\Coroutine;
use Throwable;

/**
 * A server runner that uses Swoole coroutines instead of forked processes.
 *
 * Each incoming client connection is handled in its own coroutine within a
 * single PHP process. This means all coroutines share the same memory, making
 * in-memory storage adapters safe to use with concurrent clients.
 *
 * Swoole's runtime coroutine hooks (SWOOLE_HOOK_ALL) are enabled automatically,
 * converting standard blocking PHP I/O (streams, sockets, file access) into
 * non-blocking coroutine yields. This allows the existing FreeDSx\Socket
 * implementation to work without modification.
 *
 * Requirements:
 *  - The swoole PHP extension must be installed.
 *  - PHP 8.1 or higher.
 *
 * Note on JsonFileStorageAdapter: although Swoole hooks make file reads
 * coroutine-friendly, flock() may still cause brief stalls under high write
 * concurrency. For write-heavy workloads prefer the InMemoryStorageAdapter.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SwooleServerRunner implements ServerRunnerInterface
{
    private const SOCKET_ACCEPT_TIMEOUT = 5;

    public function __construct(
        private readonly ServerProtocolFactory $serverProtocolFactory,
        private readonly ?LoggerInterface $logger = null,
    ) {
        if (!extension_loaded('swoole')) {
            throw new RuntimeException(
                'The Swoole extension is required to use SwooleServerRunner. '
                . 'Install it via PECL: pecl install swoole'
            );
        }
    }

    public function run(SocketServer $server): void
    {
        // Hook all standard PHP blocking I/O so it works inside coroutines.
        \Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

        Coroutine\run(function () use ($server): void {
            $this->acceptClients($server);
        });
    }

    private function acceptClients(SocketServer $server): void
    {
        $this->logger?->info('SwooleServerRunner: accepting clients.');

        while ($server->isConnected()) {
            $socket = $server->accept(self::SOCKET_ACCEPT_TIMEOUT);

            if ($socket === null) {
                continue;
            }

            Coroutine::create(function () use ($socket): void {
                $this->handleClient($socket);
            });
        }

        $this->logger?->info('SwooleServerRunner: server loop ended.');
    }

    private function handleClient(Socket $socket): void
    {
        try {
            $handler = $this->serverProtocolFactory->make($socket);
            $handler->handle();
        } catch (Throwable $e) {
            $this->logger?->error(
                'SwooleServerRunner: unhandled error in client coroutine: ' . $e->getMessage()
            );
        } finally {
            $socket->close();
        }
    }
}
