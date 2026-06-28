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

namespace FreeDSx\Ldap\Server\Logging;

use Throwable;

/**
 * Exception logging helper methods.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ExceptionLogging
{
    /**
     * @return array<string, string>
     */
    public static function makeLogContext(
        Throwable $exception,
        bool $includeTrace = false,
    ): array {
        $context = [
            EventContext::EXCEPTION_CLASS => $exception::class,
            EventContext::EXCEPTION_MESSAGE => $exception->getMessage(),
            EventContext::EXCEPTION_ORIGIN => $exception->getFile() . ':' . $exception->getLine(),
        ];

        if ($includeTrace) {
            $context[EventContext::EXCEPTION_TRACE] = $exception->getTraceAsString();
        }

        return $context;
    }
}
