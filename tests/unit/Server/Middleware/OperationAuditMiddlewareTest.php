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

namespace Tests\Unit\FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\SchemaRuleException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Write\SchemaViolationDisposition;
use FreeDSx\Ldap\Server\Backend\Write\SchemaViolations;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\OperationAuditor;
use FreeDSx\Ldap\Server\Middleware\OperationAuditMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Operation\WriteOperationResult;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;
use Tests\Support\FreeDSx\Ldap\Middleware\StubMiddlewareHandler;
use Tests\Support\FreeDSx\Ldap\Middleware\ThrowingMiddlewareHandler;

final class OperationAuditMiddlewareTest extends TestCase
{
    private RecordingLogger $logger;

    private OperationAuditMiddleware $subject;

    private ServerRequestContext $context;

    protected function setUp(): void
    {
        $this->logger = new RecordingLogger();
        $this->subject = new OperationAuditMiddleware(new OperationAuditor(new EventLogger(
            $this->logger,
            EventLogPolicy::all(),
        )));
        $this->context = new ServerRequestContext(
            new LdapMessageRequest(1, new AddRequest(Entry::create('cn=foo,dc=bar'))),
            BindToken::fromDn(
                'cn=alice,dc=bar',
            ),
        );
    }

    public function test_it_records_an_auditable_result(): void
    {
        $this->subject->process(
            $this->context,
            new StubMiddlewareHandler(WriteOperationResult::success(
                $this->context->message,
                new SchemaViolations(),
            )),
        );

        self::assertSame(
            'entry.added',
            $this->logger->records[0]['message'],
        );
    }

    public function test_it_does_not_record_a_non_auditable_result(): void
    {
        $this->subject->process(
            $this->context,
            new StubMiddlewareHandler(OperationOutcomeResult::succeeded()),
        );

        self::assertSame(
            [],
            $this->logger->records,
        );
    }

    public function test_it_returns_the_result_from_the_next_handler_unchanged(): void
    {
        $result = OperationOutcomeResult::failed();

        self::assertSame(
            $result,
            $this->subject->process(
                $this->context,
                new StubMiddlewareHandler($result),
            ),
        );
    }

    public function test_it_audits_a_write_authorization_denial_and_rethrows(): void
    {
        $exception = new OperationException(
            'Denied.',
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
        );

        $this->processThrowing($this->context, $exception);

        self::assertTrue($this->wasLogged('authz.denied.write'));
    }

    public function test_it_audits_a_search_authorization_denial(): void
    {
        $context = $this->contextFor((new SearchRequest(Filters::present('cn')))->base('dc=bar'));
        $exception = new OperationException(
            'Denied.',
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
        );

        $this->processThrowing($context, $exception);

        self::assertTrue($this->wasLogged('authz.denied.read'));
    }

    public function test_it_audits_a_critical_control_rejection(): void
    {
        $exception = new OperationException(
            'Critical control 1.2.3.4 is not supported.',
            ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
        );

        $this->processThrowing($this->context, $exception);

        self::assertTrue($this->wasLogged('control.critical.rejected'));
    }

    public function test_it_records_schema_violations_from_a_schema_rule_exception(): void
    {
        $violations = new SchemaViolations();
        $violations->record(
            new OperationException(
                'objectClass violation.',
                ResultCode::OBJECT_CLASS_VIOLATION,
            ),
            SchemaViolationDisposition::Rejected,
        );
        $exception = new SchemaRuleException(
            new OperationException(
                'objectClass violation.',
                ResultCode::OBJECT_CLASS_VIOLATION,
            ),
            $violations,
        );

        $this->processThrowing($this->context, $exception);

        self::assertTrue($this->wasLogged('schema.violation'));
    }

    public function test_it_rethrows_the_caught_operation_exception(): void
    {
        $exception = new OperationException('Boom.');

        $this->expectExceptionObject($exception);

        $this->subject->process(
            $this->context,
            new ThrowingMiddlewareHandler($exception),
        );
    }

    private function processThrowing(
        ServerRequestContext $context,
        OperationException $exception,
    ): void {
        try {
            $this->subject->process(
                $context,
                new ThrowingMiddlewareHandler($exception),
            );
            self::fail('Expected the OperationException to be re-thrown.');
        } catch (OperationException) {
        }
    }

    private function wasLogged(string $event): bool
    {
        foreach ($this->logger->records as $record) {
            if ($record['message'] === $event) {
                return true;
            }
        }

        return false;
    }

    private function contextFor(RequestInterface $request): ServerRequestContext
    {
        return new ServerRequestContext(
            new LdapMessageRequest(1, $request),
            BindToken::fromDn(
                'cn=alice,dc=bar',
            ),
        );
    }
}
