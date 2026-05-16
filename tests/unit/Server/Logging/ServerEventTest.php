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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

final class ServerEventTest extends TestCase
{
    private const VALID_LEVELS = [
        LogLevel::EMERGENCY,
        LogLevel::ALERT,
        LogLevel::CRITICAL,
        LogLevel::ERROR,
        LogLevel::WARNING,
        LogLevel::NOTICE,
        LogLevel::INFO,
        LogLevel::DEBUG,
    ];

    public function test_every_case_maps_to_a_valid_psr3_level(): void
    {
        foreach (ServerEvent::cases() as $event) {
            self::assertContains(
                $event->level(),
                self::VALID_LEVELS,
                $event->value,
            );
        }
    }

    public function test_every_case_has_a_non_empty_message_template(): void
    {
        foreach (ServerEvent::cases() as $event) {
            self::assertNotEmpty(
                $event->messageTemplate(),
                $event->value,
            );
        }
    }

    #[DataProvider('provideExceptionDiscriminationCases')]
    public function test_from_operation_exception_with_fallback_maps_codes_to_events(
        int $resultCode,
        ServerEvent $expected,
    ): void {
        $exception = new OperationException(
            'boom',
            $resultCode,
        );

        self::assertSame(
            $expected,
            ServerEvent::fromOperationException(
                $exception,
                ServerEvent::AuthorizationDeniedWrite,
                ServerEvent::PasswordModifyFailed,
            ),
        );
    }

    public function test_from_operation_exception_returns_null_for_unmatched_codes_when_no_fallback(): void
    {
        $exception = new OperationException(
            'No such object',
            ResultCode::NO_SUCH_OBJECT,
        );

        self::assertNull(ServerEvent::fromOperationException(
            $exception,
            ServerEvent::AuthorizationDeniedWrite,
        ));
    }

    /**
     * @return array<string, array{int, ServerEvent}>
     */
    public static function provideExceptionDiscriminationCases(): array
    {
        return [
            'insufficient access rights = denial event' => [
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                ServerEvent::AuthorizationDeniedWrite,
            ],
            'unavailable critical extension' => [
                ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
                ServerEvent::CriticalControlRejected,
            ],
            'object class violation' => [
                ResultCode::OBJECT_CLASS_VIOLATION,
                ServerEvent::SchemaViolation,
            ],
            'invalid attribute syntax' => [
                ResultCode::INVALID_ATTRIBUTE_SYNTAX,
                ServerEvent::SchemaViolation,
            ],
            'not allowed on RDN' => [
                ResultCode::NOT_ALLOWED_ON_RDN,
                ServerEvent::SchemaViolation,
            ],
            'naming violation' => [
                ResultCode::NAMING_VIOLATION,
                ServerEvent::SchemaViolation,
            ],
            'object class mods prohibited' => [
                ResultCode::OBJECT_CLASS_MODS_PROHIBITED,
                ServerEvent::SchemaViolation,
            ],
            'constraint violation' => [
                ResultCode::CONSTRAINT_VIOLATION,
                ServerEvent::SchemaViolation,
            ],
            'no such attribute' => [
                ResultCode::NO_SUCH_ATTRIBUTE,
                ServerEvent::SchemaViolation,
            ],
            'undefined attribute type' => [
                ResultCode::UNDEFINED_ATTRIBUTE_TYPE,
                ServerEvent::SchemaViolation,
            ],
            'attribute or value exists' => [
                ResultCode::ATTRIBUTE_OR_VALUE_EXISTS,
                ServerEvent::SchemaViolation,
            ],
            'other code = fallback' => [
                ResultCode::OTHER,
                ServerEvent::PasswordModifyFailed,
            ],
        ];
    }
}
