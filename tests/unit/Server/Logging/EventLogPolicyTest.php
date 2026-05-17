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

use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use PHPUnit\Framework\TestCase;

final class EventLogPolicyTest extends TestCase
{
    private const DEFAULT_ENABLED = [
        ServerEvent::BindSuccess,
        ServerEvent::BindFailure,
        ServerEvent::BindAnonymous,
        ServerEvent::StartTlsSucceeded,
        ServerEvent::StartTlsFailed,
        ServerEvent::PasswordModifySuccess,
        ServerEvent::PasswordModifyFailed,
        ServerEvent::AuthorizationDeniedWrite,
        ServerEvent::AuthorizationDeniedRead,
        ServerEvent::CriticalControlRejected,
        ServerEvent::SchemaViolation,
        ServerEvent::NoticeOfDisconnectSent,
        ServerEvent::PasswordPolicyAccountLocked,
        ServerEvent::PasswordPolicyAccountUnlocked,
        ServerEvent::PasswordPolicyExpired,
        ServerEvent::PasswordPolicyMustChange,
        ServerEvent::PasswordPolicyGraceLogin,
        ServerEvent::PasswordPolicyChangeRejected,
    ];

    private const AUDIT_TRAIL_ENABLED = [
        ServerEvent::EntryAdded,
        ServerEvent::EntryModified,
        ServerEvent::EntryDeleted,
        ServerEvent::EntryRenamed,
        ServerEvent::SearchAuthorized,
        ServerEvent::CompareCompleted,
    ];

    public function test_default_enables_security_relevant_events(): void
    {
        $policy = EventLogPolicy::default();

        foreach (self::DEFAULT_ENABLED as $event) {
            self::assertTrue(
                $policy->isEnabled($event),
                $event->value,
            );
        }
        foreach (self::AUDIT_TRAIL_ENABLED as $event) {
            self::assertFalse(
                $policy->isEnabled($event),
                $event->value,
            );
        }
    }

    public function test_with_audit_trail_enables_per_operation_success_events_on_top_of_default(): void
    {
        $policy = EventLogPolicy::default()->withAuditTrail();

        foreach (self::DEFAULT_ENABLED as $event) {
            self::assertTrue(
                $policy->isEnabled($event),
                $event->value,
            );
        }
        foreach (self::AUDIT_TRAIL_ENABLED as $event) {
            self::assertTrue(
                $policy->isEnabled($event),
                $event->value,
            );
        }
    }

    public function test_all_enables_every_case(): void
    {
        $policy = EventLogPolicy::all();

        foreach (ServerEvent::cases() as $event) {
            self::assertTrue(
                $policy->isEnabled($event),
                $event->value,
            );
        }
    }

    public function test_none_disables_every_case(): void
    {
        $policy = EventLogPolicy::none();

        foreach (ServerEvent::cases() as $event) {
            self::assertFalse(
                $policy->isEnabled($event),
                $event->value,
            );
        }
    }

    public function test_enable_returns_a_new_instance_and_does_not_mutate(): void
    {
        $original = EventLogPolicy::none();
        $enabled = $original->enable(ServerEvent::BindSuccess);

        self::assertNotSame(
            $original,
            $enabled,
        );
        self::assertFalse($original->isEnabled(ServerEvent::BindSuccess));
        self::assertTrue($enabled->isEnabled(ServerEvent::BindSuccess));
    }

    public function test_disable_returns_a_new_instance_and_does_not_mutate(): void
    {
        $original = EventLogPolicy::all();
        $disabled = $original->disable(ServerEvent::BindSuccess);

        self::assertNotSame(
            $original,
            $disabled,
        );
        self::assertTrue($original->isEnabled(ServerEvent::BindSuccess));
        self::assertFalse($disabled->isEnabled(ServerEvent::BindSuccess));
    }

    public function test_enable_is_idempotent(): void
    {
        $policy = EventLogPolicy::none()
            ->enable(ServerEvent::BindSuccess)
            ->enable(ServerEvent::BindSuccess);

        self::assertTrue($policy->isEnabled(ServerEvent::BindSuccess));
    }

    public function test_disable_is_idempotent(): void
    {
        $policy = EventLogPolicy::all()
            ->disable(ServerEvent::BindSuccess)
            ->disable(ServerEvent::BindSuccess);

        self::assertFalse($policy->isEnabled(ServerEvent::BindSuccess));
    }

    public function test_exception_traces_are_off_by_default(): void
    {
        self::assertFalse(EventLogPolicy::default()->includesExceptionTraces());
        self::assertFalse(EventLogPolicy::all()->includesExceptionTraces());
        self::assertFalse(EventLogPolicy::none()->includesExceptionTraces());
    }

    public function test_with_exception_traces_returns_a_new_instance_with_the_flag_set(): void
    {
        $original = EventLogPolicy::default();
        $verbose = $original->withExceptionTraces();

        self::assertNotSame(
            $original,
            $verbose,
        );
        self::assertFalse($original->includesExceptionTraces());
        self::assertTrue($verbose->includesExceptionTraces());
    }

    public function test_exception_traces_flag_is_preserved_across_enable_and_disable(): void
    {
        $policy = EventLogPolicy::default()
            ->withExceptionTraces()
            ->enable(ServerEvent::EntryAdded)
            ->disable(ServerEvent::BindSuccess);

        self::assertTrue($policy->includesExceptionTraces());
    }
}
