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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Journal;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionPolicy;
use PHPUnit\Framework\TestCase;

final class RetentionPolicyTest extends TestCase
{
    public function test_it_allows_unbounded_axes(): void
    {
        $policy = new RetentionPolicy();

        self::assertNull($policy->maxRecords);
        self::assertNull($policy->maxAgeSeconds);
    }

    public function test_it_rejects_a_non_positive_record_limit(): void
    {
        self::expectException(InvalidArgumentException::class);

        new RetentionPolicy(maxRecords: 0);
    }

    public function test_it_rejects_a_non_positive_age_limit(): void
    {
        self::expectException(InvalidArgumentException::class);

        new RetentionPolicy(maxAgeSeconds: 0);
    }
}
