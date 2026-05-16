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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Wraps a (nullable) PSR-3 logger with policy-gated, structured server events.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class EventLogger
{
    /**
     * @param array<string, mixed> $context Connection-scope context merged into every emitted event.
     */
    public function __construct(
        private ?LoggerInterface $logger,
        private EventLogPolicy $policy = new EventLogPolicy(),
        private array $context = [],
    ) {}

    /**
     * @param array<string, mixed> $context Merged on top of the existing context
     */
    public function withContext(array $context): self
    {
        return new self(
            $this->logger,
            $this->policy,
            array_merge($this->context, $context),
        );
    }

    public function isEnabled(ServerEvent $event): bool
    {
        return $this->logger !== null && $this->policy->isEnabled($event);
    }

    /**
     * @return array<string, mixed>
     */
    public function exceptionContextFor(?Throwable $cause): array
    {
        if ($cause === null) {
            return [];
        }

        $context = [
            EventContext::EXCEPTION_CLASS => $cause::class,
            EventContext::EXCEPTION_MESSAGE => $cause->getMessage(),
            EventContext::EXCEPTION_ORIGIN => $cause->getFile() . ':' . $cause->getLine(),
        ];

        if ($this->policy->includesExceptionTraces()) {
            $context[EventContext::EXCEPTION_TRACE] = $cause->getTraceAsString();
        }

        return $context;
    }

    /**
     * Builds the `subject` sub-array for an event from the bound token.
     *
     * @return array<string, mixed>
     */
    public static function subjectFromToken(TokenInterface $token): array
    {
        if ($token instanceof AuthenticatedTokenInterface) {
            return [
                EventContext::USERNAME => $token->getUsername(),
                EventContext::DN => $token->getResolvedDn()->toString(),
            ];
        }

        $username = $token->getUsername();

        if ($username === null || $username === '') {
            return [];
        }

        return [EventContext::USERNAME => $username];
    }

    /**
     * @param array<string, mixed> $context Event-scope context merged on top of connection-scope context.
     * @param TokenInterface|array<string, mixed>|null $subject Default `subject` sub-array.
     * @param ?LdapMessageRequest $message When supplied, auto-injects message_id and control_oids (if non-empty).
     */
    public function record(
        ServerEvent $event,
        array $context = [],
        TokenInterface|array|null $subject = null,
        ?LdapMessageRequest $message = null,
    ): void {
        if (!$this->isEnabled($event)) {
            return;
        }

        $this->logger?->log(
            $event->level(),
            $event->messageTemplate(),
            $this->composeContext(
                $context + self::messageContext($message),
                $subject,
                [EventContext::EVENT => $event->value],
            ),
        );
    }

    /**
     * Convenience for failure paths: auto-merges {@see EventContext::RESULT_CODE} and {@see EventContext::REASON} from
     * the caught exception. Call-site keys still win on collision.
     *
     * @param array<string, mixed> $context Event-scope context merged on top of connection-scope context.
     * @param TokenInterface|array<string, mixed>|null $subject Default `subject` sub-array.
     */
    public function recordFailure(
        ServerEvent $event,
        OperationException $exception,
        array $context = [],
        TokenInterface|array|null $subject = null,
        ?LdapMessageRequest $message = null,
    ): void {
        $this->record(
            $event,
            $context + [
                EventContext::RESULT_CODE => $exception->getCode(),
                EventContext::REASON => $exception->getMessage(),
            ],
            $subject,
            $message,
        );
    }

    public function recordSearchSuccess(
        LdapMessageRequest $message,
        int $entriesReturned,
        TokenInterface $token,
    ): void {
        $request = $message->getRequest();

        if (!$request instanceof SearchRequest) {
            return;
        }

        $this->record(
            ServerEvent::SearchAuthorized,
            [
                EventContext::ENTRIES_RETURNED => $entriesReturned,
                EventContext::TARGET => self::searchTarget($request),
            ],
            subject: $token,
            message: $message,
        );
    }

    public function recordSearchFailure(
        LdapMessageRequest $message,
        OperationException $exception,
        TokenInterface $token,
    ): void {
        $event = ServerEvent::fromOperationException(
            $exception,
            ServerEvent::AuthorizationDeniedRead,
        );

        if ($event === null) {
            return;
        }

        $request = $message->getRequest();

        if (!$request instanceof SearchRequest) {
            return;
        }

        $this->recordFailure(
            $event,
            $exception,
            [EventContext::TARGET => self::searchTarget($request)],
            subject: $token,
            message: $message,
        );
    }

    /**
     * @return array<string, mixed>
     */
    private static function searchTarget(SearchRequest $request): array
    {
        return [
            EventContext::BASE_DN => (string) $request->getBaseDn(),
            EventContext::SCOPE => $request->getScope(),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function messageContext(?LdapMessageRequest $message): array
    {
        if ($message === null) {
            return [];
        }

        $oids = [];
        foreach ($message->controls() as $control) {
            $oids[] = $control->getTypeOid();
        }

        return [
            EventContext::MESSAGE_ID => $message->getMessageId(),
            EventContext::CONTROL_OIDS => $oids,
        ];
    }

    /**
     * @param array<string, mixed> $context
     * @param TokenInterface|array<string, mixed>|null $subject
     * @param array<string, mixed> $tail
     * @return array<string, mixed>
     */
    private function composeContext(
        array $context,
        TokenInterface|array|null $subject,
        array $tail,
    ): array {
        $base = $this->context;
        $subjectArray = match (true) {
            $subject instanceof TokenInterface => self::subjectFromToken($subject),
            is_array($subject) => $subject,
            default => [],
        };

        if ($subjectArray !== []) {
            $base[EventContext::SUBJECT] = $subjectArray;
        }

        return array_merge(
            $base,
            $context,
            $tail,
        );
    }
}
