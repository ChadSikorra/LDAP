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

namespace Tests\Support\FreeDSx\Ldap\Clock;

use DateTimeImmutable;
use DateTimeZone;
use FreeDSx\Ldap\Server\Clock\ClockInterface;

/**
 * Test clock with manually controlled time. Always returns UTC instants.
 */
final class FrozenClock implements ClockInterface
{
    private DateTimeImmutable $instant;

    public function __construct(DateTimeImmutable $instant)
    {
        $this->setTo($instant);
    }

    public static function fromString(string $instant): self
    {
        return new self(new DateTimeImmutable(
            $instant,
            new DateTimeZone('UTC'),
        ));
    }

    public function now(): DateTimeImmutable
    {
        return $this->instant;
    }

    public function setTo(DateTimeImmutable $instant): void
    {
        $this->instant = $instant->setTimezone(new DateTimeZone('UTC'));
    }
}
