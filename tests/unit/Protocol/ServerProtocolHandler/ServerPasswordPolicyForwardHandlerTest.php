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

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\PasswordPolicy\ForwardPasswordPolicyStateRequest;
use FreeDSx\Ldap\Operation\Request\PasswordPolicy\PasswordPolicyStateAttribute;
use FreeDSx\Ldap\Operation\Request\PasswordPolicy\PasswordPolicyStateField;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerPasswordPolicyForwardHandler;
use FreeDSx\Ldap\Server\Backend\Write\SystemChange\SystemChangeWriterInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerPasswordPolicyForwardHandlerTest extends TestCase
{
    private ServerQueue&MockObject $queue;

    private SystemChangeWriterInterface&MockObject $changeWriter;

    private ServerPasswordPolicyForwardHandler $subject;

    protected function setUp(): void
    {
        $this->queue = $this->createMock(ServerQueue::class);
        $this->changeWriter = $this->createMock(SystemChangeWriterInterface::class);
        $this->subject = new ServerPasswordPolicyForwardHandler(
            $this->queue,
            $this->changeWriter,
        );
    }

    public function test_it_applies_the_forwarded_state_as_replace_and_reset_changes(): void
    {
        $this->changeWriter
            ->expects(self::once())
            ->method('write')
            ->with(
                self::callback(fn(Dn $dn): bool => $dn->toString() === 'cn=user,dc=foo,dc=bar'),
                self::callback(function (OperationalChanges $changes): bool {
                    [$failure, $locked] = $changes->changes;

                    return $failure->getType() === Change::TYPE_REPLACE
                        && $failure->getAttribute()->getName() === 'pwdFailureTime'
                        && $failure->getAttribute()->getValues() === ['20260101000000Z']
                        && $locked->getType() === Change::TYPE_DELETE
                        && $locked->getAttribute()->getValues() === [];
                }),
            );

        $result = $this->subject->handleRequest(
            $this->messageFor(new ForwardPasswordPolicyStateRequest(
                'cn=user,dc=foo,dc=bar',
                'uuid-1',
                [
                    new PasswordPolicyStateAttribute(
                        PasswordPolicyStateField::FailureTime,
                        ['20260101000000Z'],
                    ),
                    PasswordPolicyStateAttribute::clear(PasswordPolicyStateField::AccountLockedTime),
                ],
            )),
            $this->createMock(TokenInterface::class),
        );

        self::assertSame(
            ResultCode::SUCCESS,
            $result->resultCode(),
        );
    }

    public function test_it_sends_a_success_extended_response(): void
    {
        $this->queue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::callback(function (LdapMessageResponse $response): bool {
                $extended = $response->getResponse();

                return $extended instanceof ExtendedResponse
                    && $extended->getResultCode() === ResultCode::SUCCESS;
            }));

        $this->subject->handleRequest(
            $this->messageFor(new ForwardPasswordPolicyStateRequest('cn=user,dc=foo,dc=bar')),
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

    private function messageFor(ExtendedRequest $request): LdapMessageRequest
    {
        return new LdapMessageRequest(
            1,
            $request,
        );
    }
}
