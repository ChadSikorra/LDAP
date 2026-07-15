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

namespace FreeDSx\Ldap\Server\PasswordPolicy;

use DateTimeImmutable;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Clock\ClockInterface;

use function crc32;
use function intdiv;

/**
 * Stamps pwdFailureTime / pwdGraceUseTime values that stay unique within and across replicas, as draft-behera password
 * policy recommends, by packing a replica hash and an intra-second counter into the microsecond field.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class UniquePolicyTimeFactory
{
    /**
     * The high 4 digits of the microsecond field, so cross-replica hash collisions land at about one in ten thousand.
     */
    private const BAND_MODULUS = 10000;

    /**
     * The low 2 digits of the microsecond field; failures stop accruing once an account locks, so it never nears 100.
     */
    private const COUNTER_MODULUS = 100;

    /**
     * The replica's fixed slice of the microsecond field; a hash collision only under-counts by one for a shared
     * subject in the same second, which is fail-safe and within the spec's "local matter" latitude.
     */
    private int $replicaBand;

    public function __construct(
        private ClockInterface $clock,
        ReplicaId $replicaId,
    ) {
        $this->replicaBand = (int) (crc32((string) $replicaId) % self::BAND_MODULUS);
    }

    /**
     * The current time stamped unique against $existing, which the caller must read under the same lock that persists
     * the result so the counter cannot race.
     *
     * @param list<DateTimeImmutable> $existing
     */
    public function next(array $existing): DateTimeImmutable
    {
        $whole = $this->clock
            ->now()
            ->setTime(
                (int) $this->clock->now()->format('H'),
                (int) $this->clock->now()->format('i'),
                (int) $this->clock->now()->format('s'),
            );

        $microseconds = $this->replicaBand * self::COUNTER_MODULUS
            + $this->sameBandCount($existing, $whole) % self::COUNTER_MODULUS;

        return $whole->setTime(
            (int) $whole->format('H'),
            (int) $whole->format('i'),
            (int) $whole->format('s'),
            $microseconds,
        );
    }

    /**
     * @param list<DateTimeImmutable> $existing
     */
    private function sameBandCount(
        array $existing,
        DateTimeImmutable $whole,
    ): int {
        $second = $whole->format('YmdHis');
        $count = 0;

        foreach ($existing as $time) {
            if ($time->format('YmdHis') !== $second) {
                continue;
            }

            if (intdiv((int) $time->format('u'), self::COUNTER_MODULUS) === $this->replicaBand) {
                $count++;
            }
        }

        return $count;
    }
}
