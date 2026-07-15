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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy;

use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\PasswordPolicy\UniquePolicyTimeFactory;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;

final class UniquePolicyTimeFactoryTest extends TestCase
{
    private const NOW = '2026-05-20T12:00:00Z';

    public function test_it_stamps_the_current_whole_second(): void
    {
        $stamped = $this->factory('r1')->next([]);

        self::assertSame(
            '20260520120000',
            $stamped->format('YmdHis'),
        );
    }

    public function test_successive_stamps_in_the_same_second_are_distinct(): void
    {
        $factory = $this->factory('r1');

        $first = $factory->next([]);
        $second = $factory->next([$first]);

        self::assertNotEquals(
            $first->format('u'),
            $second->format('u'),
        );
    }

    public function test_different_replicas_stamp_distinct_values_in_the_same_second(): void
    {
        $fromA = $this->factory('replica-a')->next([]);
        $fromB = $this->factory('replica-b')->next([]);

        self::assertNotEquals(
            $fromA->format('u'),
            $fromB->format('u'),
        );
    }

    public function test_a_foreign_replicas_prior_failure_does_not_advance_the_counter(): void
    {
        $foreign = $this->factory('other')->next([]);
        $factory = $this->factory('r1');

        self::assertEquals(
            $factory->next([]),
            $factory->next([$foreign]),
        );
    }

    private function factory(string $replicaId): UniquePolicyTimeFactory
    {
        return new UniquePolicyTimeFactory(
            FrozenClock::fromString(self::NOW),
            new ReplicaId($replicaId),
        );
    }
}
