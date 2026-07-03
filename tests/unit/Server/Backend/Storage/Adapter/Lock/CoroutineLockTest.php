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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\CoroutineLock;
use PHPUnit\Framework\TestCase;
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;

final class CoroutineLockTest extends TestCase
{
    private string $tempFile = '';

    protected function setUp(): void
    {
        if (!extension_loaded('swoole')) {
            $this->markTestSkipped('The swoole extension is required for this test.');
        }

        $this->tempFile = sys_get_temp_dir() . '/ldap_test_corolock_' . uniqid() . '.dat';
    }

    protected function tearDown(): void
    {
        if ($this->tempFile === '') {
            return;
        }

        foreach ([$this->tempFile, $this->tempFile . '.lock'] as $path) {
            if (file_exists($path)) {
                unlink($path);
            }
        }
    }

    public function test_with_exclusive_runs_the_callback(): void
    {
        $lock = new CoroutineLock($this->tempFile);
        $ran = false;

        Coroutine\run(function () use ($lock, &$ran): void {
            $lock->withExclusive(function () use (&$ran): void {
                $ran = true;
            });
        });

        self::assertTrue($ran);
    }

    public function test_it_is_reentrant_within_a_single_coroutine(): void
    {
        $lock = new CoroutineLock($this->tempFile);
        $ran = false;

        Coroutine\run(function () use ($lock, &$ran): void {
            $lock->withExclusive(function () use ($lock, &$ran): void {
                // A nested acquire in the same coroutine must not deadlock on the Channel(1) mutex.
                $lock->withExclusive(function () use (&$ran): void {
                    $ran = true;
                });
            });
        });

        self::assertTrue($ran);
    }

    public function test_a_second_coroutine_cannot_enter_while_another_holds_the_lock(): void
    {
        // Directly targets the per-coroutine depth: a shared instance counter would let B see A's depth and
        // skip the mutex, entering the critical section while A still holds it.
        $lock = new CoroutineLock($this->tempFile);
        $events = [];

        Coroutine\run(function () use ($lock, &$events): void {
            $aHolding = new Channel(1);
            $done = new Channel(2);

            Coroutine::create(function () use ($lock, $aHolding, $done, &$events): void {
                $lock->withExclusive(function () use ($aHolding, &$events): void {
                    $aHolding->push(true);
                    Coroutine::sleep(0.03);
                    $events[] = 'a-release';
                });
                $done->push(true);
            });

            Coroutine::create(function () use ($lock, $aHolding, $done, &$events): void {
                $aHolding->pop();

                $lock->withExclusive(function () use (&$events): void {
                    $events[] = 'b-enter';
                });
                $done->push(true);
            });

            $done->pop();
            $done->pop();
        });

        // B entered only after A released: no interleaving.
        self::assertSame(
            ['a-release', 'b-enter'],
            $events,
        );
    }

    public function test_reentry_in_one_coroutine_does_not_release_the_lock_for_another(): void
    {
        // A enters twice (re-entrant) then exits its inner scope; the lock must remain held for A, so B still
        // cannot enter until A fully unwinds. A shared counter would drop to zero on the inner exit.
        $lock = new CoroutineLock($this->tempFile);
        $events = [];

        Coroutine\run(function () use ($lock, &$events): void {
            $aHolding = new Channel(1);
            $done = new Channel(2);

            Coroutine::create(function () use ($lock, $aHolding, $done, &$events): void {
                $lock->withExclusive(function () use ($lock, $aHolding, &$events): void {
                    $lock->withExclusive(function (): void {
                        // inner re-entry
                    });
                    $aHolding->push(true);
                    Coroutine::sleep(0.03);
                    $events[] = 'a-release';
                });
                $done->push(true);
            });

            Coroutine::create(function () use ($lock, $aHolding, $done, &$events): void {
                $aHolding->pop();

                $lock->withExclusive(function () use (&$events): void {
                    $events[] = 'b-enter';
                });
                $done->push(true);
            });

            $done->pop();
            $done->pop();
        });

        self::assertSame(
            ['a-release', 'b-enter'],
            $events,
        );
    }
}
