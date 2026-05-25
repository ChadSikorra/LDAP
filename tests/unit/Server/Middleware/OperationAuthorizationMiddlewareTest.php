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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\HandlerId;
use FreeDSx\Ldap\Protocol\Factory\HandlerRouteResolverInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\OperationType;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Middleware\OperationAuthorizationMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;
use Tests\Support\FreeDSx\Ldap\Middleware\CallLog;
use Tests\Support\FreeDSx\Ldap\Middleware\RecordingMiddlewareHandler;

final class OperationAuthorizationMiddlewareTest extends TestCase
{
    private HandlerRouteResolverInterface&MockObject $resolver;

    private AccessControlInterface&MockObject $accessControl;

    private RecordingLogger $logger;

    private TokenInterface&MockObject $token;

    private OperationAuthorizationMiddleware $subject;

    private RecordingMiddlewareHandler $next;

    protected function setUp(): void
    {
        $this->resolver = $this->createMock(HandlerRouteResolverInterface::class);
        $this->accessControl = $this->createMock(AccessControlInterface::class);
        $this->logger = new RecordingLogger();
        $this->token = $this->createMock(TokenInterface::class);
        $this->subject = new OperationAuthorizationMiddleware(
            $this->resolver,
            $this->accessControl,
            new EventLogger(
                $this->logger,
                EventLogPolicy::default(),
            ),
        );
        $this->next = new RecordingMiddlewareHandler(new CallLog());
    }

    public function test_search_route_authorizes_the_search_operation_then_continues(): void
    {
        $this->routeResolvesTo(HandlerId::Search);
        $this->accessControl
            ->expects(self::once())
            ->method('authorizeOperation')
            ->with(
                OperationType::Search,
                $this->token,
                self::isInstanceOf(Dn::class),
            );

        $this->subject->process(
            $this->contextFor((new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar')),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_search_route_denial_audits_a_read_denial_and_blocks_dispatch(): void
    {
        $this->routeResolvesTo(HandlerId::Paging);
        $this->accessControl
            ->method('authorizeOperation')
            ->willThrowException($this->denied());

        try {
            $this->subject->process(
                $this->contextFor((new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar')),
                $this->next,
            );
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                $e->getCode(),
            );
        }

        self::assertNull(
            $this->next->received,
            'Dispatch must be blocked on denial.',
        );
        self::assertTrue($this->wasLogged('authz.denied.read'));
    }

    public function test_dispatch_route_authorizes_modify_dn_against_source_only(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $this->accessControl
            ->expects(self::once())
            ->method('authorizeOperation')
            ->with(
                OperationType::ModifyDn,
                $this->token,
                self::isInstanceOf(Dn::class),
            );

        $this->subject->process(
            $this->contextFor(new ModifyDnRequest('cn=foo,dc=bar', 'cn=baz', true)),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_dispatch_route_authorizes_modify_dn_against_source_and_new_superior(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $this->accessControl
            ->expects(self::exactly(2))
            ->method('authorizeOperation')
            ->with(
                OperationType::ModifyDn,
                $this->token,
                self::isInstanceOf(Dn::class),
            );

        $this->subject->process(
            $this->contextFor(new ModifyDnRequest('cn=foo,dc=bar', 'cn=baz', true, 'ou=other,dc=bar')),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_dispatch_route_add_attribute_denial_audits_a_write_denial_and_blocks_dispatch(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $this->accessControl
            ->method('authorizeAttribute')
            ->willThrowException($this->denied());

        $message = $this->contextFor(new AddRequest(Entry::create(
            'cn=foo,dc=bar',
            ['userpassword' => 'secret'],
        )));

        try {
            $this->subject->process($message, $this->next);
            self::fail('Expected an OperationException.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                $e->getCode(),
            );
        }

        self::assertNull($this->next->received);
        self::assertTrue($this->wasLogged('authz.denied.write'));
    }

    public function test_dispatch_route_compare_attribute_denial_blocks_dispatch(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $this->accessControl
            ->method('authorizeAttribute')
            ->willThrowException($this->denied());

        $message = $this->contextFor(new CompareRequest(
            'cn=foo,dc=bar',
            Filters::equal('userpassword', 'secret'),
        ));

        try {
            $this->subject->process($message, $this->next);
            self::fail('Expected an OperationException.');
        } catch (OperationException) {
        }

        self::assertNull($this->next->received);
    }

    public function test_dispatch_route_authorizes_a_privileged_control_against_the_target(): void
    {
        $this->routeResolvesTo(HandlerId::Dispatch);
        $this->accessControl
            ->expects(self::once())
            ->method('authorizeControl')
            ->with(
                $this->token,
                self::isInstanceOf(Dn::class),
                Control::OID_RELAX_RULES,
            );

        $message = new LdapMessageRequest(
            1,
            new DeleteRequest('cn=foo,dc=bar'),
            new Control(Control::OID_RELAX_RULES, criticality: true),
        );

        $this->subject->process(
            new ServerRequestContext($message, $this->token),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    #[DataProvider('unauthorizedRoutes')]
    public function test_routes_without_operation_authorization_are_not_gated(HandlerId $routeId): void
    {
        $this->routeResolvesTo($routeId);
        $this->accessControl
            ->expects(self::never())
            ->method('authorizeOperation');

        $this->subject->process(
            $this->contextFor((new SearchRequest(Filters::present('cn')))->base('')),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    /**
     * @return iterable<string, array{HandlerId}>
     */
    public static function unauthorizedRoutes(): iterable
    {
        yield 'root dse' => [HandlerId::RootDse];
        yield 'subschema' => [HandlerId::Subschema];
        yield 'whoami' => [HandlerId::WhoAmI];
        yield 'start tls' => [HandlerId::StartTls];
        yield 'cancel' => [HandlerId::Cancel];
        yield 'unbind' => [HandlerId::Unbind];
    }

    private function routeResolvesTo(HandlerId $id): void
    {
        $this->resolver
            ->method('routeIdFor')
            ->willReturn($id);
    }

    private function contextFor(RequestInterface $request): ServerRequestContext
    {
        return new ServerRequestContext(
            new LdapMessageRequest(1, $request),
            $this->token,
        );
    }

    private function denied(): OperationException
    {
        return new OperationException(
            'Access denied.',
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
        );
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
}
