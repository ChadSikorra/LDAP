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

namespace Tests\Integration\FreeDSx\Ldap\Security;

use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashVerifier;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\Backend\Write\PasswordPolicyWriteHandler;
use FreeDSx\Ldap\Server\Backend\Write\SystemChangeWriter;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerDispatchHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\DispatchEventRecorder;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\AllowUserChangeConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\HistoryConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\MinAgeConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\PasswordChangeConstraintChain;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\QualityConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Constraint\SafeModifyConstraint;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyChangeGuard;
use FreeDSx\Ldap\Server\PasswordPolicy\HistoryEntry;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\DefaultPasswordQualityChecker;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Clock\FrozenClock;

/**
 * In-process integration of a plain ldapmodify of userPassword flowing through the dispatch handler.
 */
final class PasswordPolicyPlainModifyEnforcementTest extends TestCase
{
    private const NOW = '2026-05-20T12:00:00Z';
    private const USER_DN = 'cn=user,dc=foo,dc=bar';

    private FrozenClock $clock;
    private WritableStorageBackend $backend;
    private PasswordPolicyContext $context;
    private ?LdapMessageResponse $response = null;

    protected function setUp(): void
    {
        $this->clock = FrozenClock::fromString(self::NOW);
        $this->context = new PasswordPolicyContext();
    }

    public function test_reused_password_is_rejected_with_history_control(): void
    {
        $handler = $this->dispatchHandler(
            new PasswordPolicy(quality: new PasswordQualityRules(inHistory: 5)),
            [PasswordPolicyOid::NAME_PWD_HISTORY => $this->historyValue('previous-pass')],
        );

        $handler->handleRequest(
            $this->modify('previous-pass'),
            $this->token(),
        );

        $response = $this->response?->getResponse();
        self::assertInstanceOf(
            LdapResult::class,
            $response,
        );
        self::assertSame(
            ResultCode::CONSTRAINT_VIOLATION,
            $response->getResultCode(),
        );

        $control = $this->response?->controls()->getByClass(PwdPolicyResponseControl::class);
        self::assertInstanceOf(
            PwdPolicyResponseControl::class,
            $control,
        );
        self::assertSame(
            PwdPolicyError::PASSWORD_IN_HISTORY,
            $control->getError(),
        );
    }

    public function test_successful_change_persists_and_records_bookkeeping(): void
    {
        $handler = $this->dispatchHandler(
            new PasswordPolicy(quality: new PasswordQualityRules(inHistory: 3)),
            [PasswordPolicyOid::NAME_PWD_RESET => 'TRUE'],
        );

        $handler->handleRequest(
            $this->modify('a-fresh-password'),
            $this->token(),
        );

        $response = $this->response?->getResponse();
        self::assertInstanceOf(
            LdapResult::class,
            $response,
        );
        self::assertSame(
            ResultCode::SUCCESS,
            $response->getResultCode(),
        );

        $entry = $this->backend->get(new Dn(self::USER_DN));
        self::assertNotNull($entry);
        self::assertTrue(
            (new PasswordHashVerifier())->verify(
                'a-fresh-password',
                (string) $entry->get('userPassword')?->firstValue(),
            ),
        );
        self::assertNotNull($entry->get(PasswordPolicyOid::NAME_PWD_CHANGED_TIME));
        self::assertNull(
            $entry->get(PasswordPolicyOid::NAME_PWD_RESET),
            'A successful change should clear pwdReset.',
        );
    }

    /**
     * @param array<string, string> $userAttrs
     */
    private function dispatchHandler(
        PasswordPolicy $policy,
        array $userAttrs = [],
    ): ServerDispatchHandler {
        $this->backend = new WritableStorageBackend(new InMemoryStorage([
            Entry::fromArray(
                'dc=foo,dc=bar',
                [
                    'objectClass' => ['domain'],
                    'dc' => ['foo'],
                ],
            ),
            Entry::fromArray(
                self::USER_DN,
                [
                    'objectClass' => ['inetOrgPerson'],
                    'cn' => ['user'],
                    'sn' => ['User'],
                    'userPassword' => ['original-pass'],
                ] + $userAttrs,
            ),
        ]));

        $guard = new PasswordPolicyChangeGuard(
            new PasswordPolicyEngine(
                clock: $this->clock,
                changeConstraints: new PasswordChangeConstraintChain([
                    new AllowUserChangeConstraint(),
                    new SafeModifyConstraint(),
                    new MinAgeConstraint($this->clock),
                    new QualityConstraint(new DefaultPasswordQualityChecker()),
                    new HistoryConstraint(new PasswordHashVerifier()),
                ]),
            ),
            new PasswordPolicyResolver(
                $this->backend,
                null,
                $policy,
            ),
            $this->context,
            new EventLogger(null),
        );
        $policyWriteHandler = new PasswordPolicyWriteHandler(
            $this->backend,
            $guard,
            new SystemChangeWriter(new WriteOperationDispatcher($this->backend)),
        );

        return new ServerDispatchHandler(
            queue: $this->capturingQueue(),
            backend: $this->backend,
            writeDispatcher: new WriteOperationDispatcher(
                $policyWriteHandler,
                $this->backend,
            ),
            accessControl: $this->createMock(AccessControlInterface::class),
            eventRecorder: new DispatchEventRecorder(new EventLogger(null)),
            passwordPolicyContext: $this->context,
        );
    }

    private function capturingQueue(): ServerQueue
    {
        $queue = $this->createMock(ServerQueue::class);
        $queue
            ->method('sendMessage')
            ->willReturnCallback(function (LdapMessageResponse $response) use ($queue): ServerQueue {
                $this->response = $response;

                return $queue;
            });

        return $queue;
    }

    private function modify(string $newPassword): LdapMessageRequest
    {
        return new LdapMessageRequest(
            1,
            new ModifyRequest(
                self::USER_DN,
                Change::replace('userPassword', $newPassword),
            ),
        );
    }

    private function token(): BindToken
    {
        return BindToken::fromDn(
            self::USER_DN,
            'original-pass',
        );
    }

    private function historyValue(string $plaintext): string
    {
        return HistoryEntry::forStoredPassword(
            $this->clock->now(),
            '{BCRYPT}' . password_hash($plaintext, PASSWORD_BCRYPT),
        )->encode();
    }
}
