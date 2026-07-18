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

namespace FreeDSx\Ldap\Protocol\Queue\Response;

use Closure;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Response\ResponseInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ConnectionControl;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use Generator;

use function array_map;

/**
 * The messages a handler wants written, plus the outcome resolved once they are drained.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ResponseStream
{
    /**
     * @param iterable<LdapMessageResponse> $messages streamed to the socket in order.
     * @param Closure(): OperationResult $outcome resolved after the stream is fully drained.
     * @param QueueWriterConfig $writerConfig how the writer batches, flushes, and polls this stream.
     * @param ?Cancellation $cancellation the writer offers polled signals here; the producer reads it.
     * @param ?Closure(ConnectionControl): void $onComplete a post-write connection action the writer
     *        runs once the stream is drained and flushed.
     */
    private function __construct(
        public iterable $messages,
        private Closure $outcome,
        public QueueWriterConfig $writerConfig = new QueueWriterConfig(),
        public ?Cancellation $cancellation = null,
        public ?Closure $onComplete = null,
    ) {}

    public function outcome(): OperationResult
    {
        return ($this->outcome)();
    }

    /**
     * A copy of this stream with a post-write connection action the writer runs after draining.
     *
     * @param Closure(ConnectionControl): void $onComplete
     */
    public function withOnComplete(Closure $onComplete): self
    {
        return new self(
            $this->messages,
            $this->outcome,
            $this->writerConfig,
            $this->cancellation,
            $onComplete,
        );
    }

    /**
     * The message generator for a stepped stream; only a generator can be polled and flushed per message.
     *
     * @return Generator<LdapMessageResponse>
     * @throws RuntimeException if the stream was not built for stepping via streaming().
     */
    public function generator(): Generator
    {
        if (!$this->messages instanceof Generator) {
            throw new RuntimeException('A stepped response stream must carry a generator.');
        }

        return $this->messages;
    }

    /**
     * A response whose outcome is already known; the default writer config bulk-sends it.
     *
     * @param iterable<LdapMessageResponse> $messages
     */
    public static function of(
        iterable $messages,
        OperationResult $outcome,
    ): self {
        return new self(
            messages: $messages,
            outcome: static fn(): OperationResult => $outcome,
        );
    }

    /**
     * One or more inner responses, each wrapped in an envelope addressed to the request's message ID.
     */
    public static function reply(
        LdapMessageRequest $message,
        OperationResult $outcome,
        ResponseInterface ...$responses,
    ): self {
        $messageId = $message->getMessageId();

        return self::of(
            array_map(
                static fn(ResponseInterface $response): LdapMessageResponse
                    => new LdapMessageResponse($messageId, $response),
                $responses,
            ),
            $outcome,
        );
    }

    /**
     * A streaming response whose outcome is resolved after draining; steps only when the config asks.
     *
     * @param Generator<LdapMessageResponse> $messages
     * @param Closure(): OperationResult $outcome
     */
    public static function streaming(
        Generator $messages,
        Closure $outcome,
        QueueWriterConfig $writerConfig = new QueueWriterConfig(),
        ?Cancellation $cancellation = null,
    ): self {
        return new self(
            messages: $messages,
            outcome: $outcome,
            writerConfig: $writerConfig,
            cancellation: $cancellation,
        );
    }

    public static function none(OperationResult $outcome): self
    {
        return self::of(
            [],
            $outcome,
        );
    }

    /**
     * An already-written response carrying only its resolved outcome, handed up past the writer.
     */
    public static function resolved(OperationResult $outcome): self
    {
        return self::none($outcome);
    }
}
