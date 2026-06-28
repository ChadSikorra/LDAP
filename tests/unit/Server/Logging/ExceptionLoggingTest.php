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

namespace Tests\Unit\FreeDSx\Ldap\Server\Logging;

use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\ExceptionLogging;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class ExceptionLoggingTest extends TestCase
{
    public function test_it_includes_class_message_and_origin_without_a_trace(): void
    {
        $context = ExceptionLogging::makeLogContext(new RuntimeException('boom'));

        self::assertSame(
            RuntimeException::class,
            $context[EventContext::EXCEPTION_CLASS],
        );
        self::assertSame(
            'boom',
            $context[EventContext::EXCEPTION_MESSAGE],
        );
        self::assertArrayHasKey(
            EventContext::EXCEPTION_ORIGIN,
            $context,
        );
        self::assertArrayNotHasKey(
            EventContext::EXCEPTION_TRACE,
            $context,
        );
    }

    public function test_it_adds_the_trace_when_requested(): void
    {
        $context = ExceptionLogging::makeLogContext(
            new RuntimeException('boom'),
            true,
        );

        self::assertArrayHasKey(
            EventContext::EXCEPTION_TRACE,
            $context,
        );
    }
}
