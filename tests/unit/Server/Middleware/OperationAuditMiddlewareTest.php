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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Server\Backend\Write\SchemaViolations;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\OperationAuditor;
use FreeDSx\Ldap\Server\Middleware\OperationAuditMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use FreeDSx\Ldap\Server\Operation\WriteOperationResult;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;

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
            new BindToken(
                'cn=alice,dc=bar',
                'secret',
                new Dn('cn=alice,dc=bar'),
            ),
        );
    }

    public function test_it_records_an_auditable_result(): void
    {
        $this->subject->process(
            $this->context,
            $this->handlerReturning(WriteOperationResult::success(
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
            $this->handlerReturning(OperationOutcomeResult::succeeded()),
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
                $this->handlerReturning($result),
            ),
        );
    }

    private function handlerReturning(OperationResult $result): MiddlewareHandlerInterface
    {
        return new class ($result) implements MiddlewareHandlerInterface {
            public function __construct(private readonly OperationResult $result) {}

            public function handle(ServerRequestContext $context): OperationResult
            {
                return $this->result;
            }
        };
    }
}
