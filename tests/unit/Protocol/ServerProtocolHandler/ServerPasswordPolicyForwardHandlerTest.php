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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use DateTimeImmutable;
use DateTimeZone;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ForwardPasswordPolicyStateRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerPasswordPolicyForwardHandler;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\SystemChange\SystemChangeWriterInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordLockoutRules;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;

final class ServerPasswordPolicyForwardHandlerTest extends TestCase
{
    private const NOW = '2026-05-20T12:00:00Z';

    private ServerQueue&MockObject $queue;

    private LdapBackendInterface&MockObject $backend;

    private SystemChangeWriterInterface&MockObject $changeWriter;

    private ServerPasswordPolicyForwardHandler $subject;

    protected function setUp(): void
    {
        $this->queue = $this->createMock(ServerQueue::class);
        $this->backend = $this->createMock(LdapBackendInterface::class);
        $this->changeWriter = $this->createMock(SystemChangeWriterInterface::class);
        $this->subject = new ServerPasswordPolicyForwardHandler(
            $this->queue,
            $this->backend,
            new PasswordPolicyResolver(
                $this->backend,
                null,
                new PasswordPolicy(lockout: new PasswordLockoutRules(
                    enabled: true,
                    maxFailure: 3,
                )),
            ),
            new PasswordPolicyEngine(
                FrozenClock::fromString(self::NOW),
                new PasswordChangeConstraintChain([]),
            ),
            $this->changeWriter,
        );
    }

    public function test_it_unions_forwarded_failures_and_writes_the_result(): void
    {
        $time = new DateTimeImmutable(
            '2026-05-20 11:59:00',
            new DateTimeZone('UTC'),
        );

        $this->backend->method('get')->willReturn(Entry::create('cn=user,dc=foo,dc=bar', ['cn' => 'user']));
        $this->changeWriter
            ->expects(self::once())
            ->method('write')
            ->with(
                self::callback(fn(Dn $dn): bool => $dn->toString() === 'cn=user,dc=foo,dc=bar'),
                self::callback($this->hasNonEmptyAttribute('pwdFailureTime')),
            );

        $result = $this->subject->handleRequest(
            $this->messageFor(new ForwardPasswordPolicyStateRequest('cn=user,dc=foo,dc=bar', 'uuid', [$time])),
            $this->createMock(TokenInterface::class),
        );

        self::assertSame(
            ResultCode::SUCCESS,
            $result->resultCode(),
        );
    }

    public function test_a_forwarded_success_clears_the_superseded_failures(): void
    {
        $success = new DateTimeImmutable(
            '2026-05-20 12:00:00',
            new DateTimeZone('UTC'),
        );

        $this->backend->method('get')->willReturn(Entry::create(
            'cn=user,dc=foo,dc=bar',
            [
                'cn' => 'user',
                'pwdFailureTime' => '20260520115000Z',
            ],
        ));
        $this->changeWriter
            ->expects(self::once())
            ->method('write')
            ->with(
                self::anything(),
                self::callback($this->attributeValues('pwdFailureTime', [])),
            );

        $this->subject->handleRequest(
            $this->messageFor(new ForwardPasswordPolicyStateRequest(
                'cn=user,dc=foo,dc=bar',
                'uuid',
                [],
                $success,
            )),
            $this->createMock(TokenInterface::class),
        );
    }

    public function test_an_unknown_entry_is_a_no_op_but_still_acks(): void
    {
        $this->backend->method('get')->willReturn(null);
        $this->changeWriter
            ->expects(self::never())
            ->method('write');
        $this->queue
            ->expects(self::once())
            ->method('sendMessage');

        $this->subject->handleRequest(
            $this->messageFor(new ForwardPasswordPolicyStateRequest(
                'cn=user,dc=foo,dc=bar',
                'uuid',
                [new DateTimeImmutable('2026-05-20 11:59:00', new DateTimeZone('UTC'))],
            )),
            $this->createMock(TokenInterface::class),
        );
    }

    public function test_it_rejects_a_request_of_the_wrong_type(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        $this->subject->handleRequest(
            $this->messageFor(new ExtendedRequest(ExtendedRequest::OID_PPOLICY_STATE_FORWARD)),
            $this->createMock(TokenInterface::class),
        );
    }

    /**
     * @return callable(OperationalChanges): bool
     */
    private function hasNonEmptyAttribute(string $name): callable
    {
        return function (OperationalChanges $changes) use ($name): bool {
            foreach ($changes->changes as $change) {
                if ($change->getAttribute()->getName() === $name && $change->getAttribute()->getValues() !== []) {
                    return true;
                }
            }

            return false;
        };
    }

    /**
     * @param list<string> $values
     * @return callable(OperationalChanges): bool
     */
    private function attributeValues(
        string $name,
        array $values,
    ): callable {
        return function (OperationalChanges $changes) use ($name, $values): bool {
            foreach ($changes->changes as $change) {
                if ($change->getAttribute()->getName() === $name) {
                    return array_values($change->getAttribute()->getValues()) === $values;
                }
            }

            return false;
        };
    }

    private function messageFor(ExtendedRequest $request): LdapMessageRequest
    {
        return new LdapMessageRequest(
            1,
            $request,
        );
    }
}
