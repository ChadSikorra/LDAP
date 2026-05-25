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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareChain;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Middleware\CallLog;
use Tests\Support\FreeDSx\Ldap\Middleware\RecordingMiddleware;
use Tests\Support\FreeDSx\Ldap\Middleware\RecordingMiddlewareHandler;
use Tests\Support\FreeDSx\Ldap\Middleware\ThrowingMiddleware;

final class MiddlewareChainTest extends TestCase
{
    private ServerRequestContext $context;

    private CallLog $log;

    protected function setUp(): void
    {
        $this->context = new ServerRequestContext(
            new LdapMessageRequest(1, new DeleteRequest('cn=foo,dc=bar')),
            $this->createMock(TokenInterface::class),
        );
        $this->log = new CallLog();
    }

    public function test_an_empty_chain_delegates_straight_to_the_terminal(): void
    {
        $subject = new MiddlewareChain(
            [],
            new RecordingMiddlewareHandler($this->log),
        );

        $subject->handle($this->context);

        self::assertSame(
            ['terminal'],
            $this->log->entries,
        );
    }

    public function test_it_nests_middleware_outer_to_inner_around_the_terminal(): void
    {
        $subject = new MiddlewareChain(
            [
                new RecordingMiddleware($this->log, 'A'),
                new RecordingMiddleware($this->log, 'B'),
            ],
            new RecordingMiddlewareHandler($this->log),
        );

        $subject->handle($this->context);

        self::assertSame(
            ['before:A', 'before:B', 'terminal', 'after:B', 'after:A'],
            $this->log->entries,
        );
    }

    public function test_a_throwing_middleware_short_circuits_the_terminal(): void
    {
        $subject = new MiddlewareChain(
            [new ThrowingMiddleware(new OperationException(
                'Rejected before dispatch.',
                ResultCode::OPERATIONS_ERROR,
            ))],
            new RecordingMiddlewareHandler($this->log),
        );

        try {
            $subject->handle($this->context);
            self::fail('Expected an OperationException to propagate.');
        } catch (OperationException) {
        }

        self::assertSame(
            [],
            $this->log->entries,
            'The terminal must not be reached when a middleware throws.',
        );
    }

    public function test_it_forwards_the_same_context_to_the_terminal(): void
    {
        $terminal = new RecordingMiddlewareHandler($this->log);
        $subject = new MiddlewareChain(
            [new RecordingMiddleware($this->log, 'A')],
            $terminal,
        );

        $subject->handle($this->context);

        self::assertSame(
            $this->context,
            $terminal->received,
        );
    }
}
