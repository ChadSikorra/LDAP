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
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use Generator;

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
     * @param ?Closure(): void $onComplete run by the writer once the stream is drained and flushed.
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
     * A response whose outcome is already known; the default writer config bulk-sends it.
     *
     * @param iterable<LdapMessageResponse> $messages
     * @param ?Closure(): void $onComplete
     */
    public static function of(
        iterable $messages,
        OperationResult $outcome,
        ?Closure $onComplete = null,
    ): self {
        return new self(
            messages: $messages,
            outcome: static fn(): OperationResult => $outcome,
            onComplete: $onComplete,
        );
    }

    /**
     * A stepped streaming response whose outcome is resolved after draining.
     *
     * @param Generator<LdapMessageResponse> $messages
     * @param Closure(): OperationResult $outcome
     */
    public static function streaming(
        Generator $messages,
        Closure $outcome,
        QueueWriterConfig $writerConfig,
        ?Cancellation $cancellation = null,
    ): self {
        return new self(
            messages: $messages,
            outcome: $outcome,
            writerConfig: $writerConfig,
            cancellation: $cancellation,
        );
    }

    /**
     * @param ?Closure(): void $onComplete
     */
    public static function none(
        OperationResult $outcome,
        ?Closure $onComplete = null,
    ): self {
        return self::of(
            messages: [],
            outcome: $outcome,
            onComplete: $onComplete,
        );
    }
}
