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

namespace FreeDSx\Ldap\Server\Middleware\Pipeline;

use FreeDSx\Ldap\Protocol\Factory\ProtocolHandlerProviderInterface;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Operation\OperationResult;

use function count;

/**
 * Terminal handler that resolves the per-request handler, writes its response, and returns its outcome.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class HandlerInvoker implements MiddlewareHandlerInterface
{
    public function __construct(
        private ProtocolHandlerProviderInterface $protocolHandlerProvider,
        private ServerQueue $queue,
    ) {}

    public function handle(ServerRequestContext $context): OperationResult
    {
        $handler = $this->protocolHandlerProvider->get(
            $context->message->getRequest(),
            $context->message->controls(),
            $context->searchLimits(),
        );

        $stream = $handler->handleRequest(
            $context->message,
            $context->tokenOrFail(),
        );
        $this->write(
            $stream,
            $context->message->getMessageId(),
        );

        return $stream->outcome();
    }

    private function write(
        ResponseStream $stream,
        int $messageId,
    ): void {
        if ($stream->writerConfig->mustFlushOrSignal()) {
            $this->step(
                $stream,
                $messageId,
            );
        } else {
            $this->queue->sendMessages($stream->messages);
        }

        // Post-write connection side effect (e.g. StartTLS encrypt) — the bytes are on the wire now.
        if ($stream->onComplete !== null) {
            ($stream->onComplete)($this->queue);
        }
    }

    /**
     * Walk the generator, flushing in batches and offering polled cancel signals at the configured interval.
     */
    private function step(
        ResponseStream $stream,
        int $messageId,
    ): void {
        $config = $stream->writerConfig;
        // Flush per message for liveness, else batch up to the poll interval.
        $flushEvery = $config->flushPerMessage
            ? 1
            : max(1, $config->signalInterval);
        $chunk = [];
        $sincePoll = 0;

        // The producer reads the offered signal from the Cancellation token when foreach resumes it.
        foreach ($stream->generator() as $message) {
            $chunk[] = $message;
            $sincePoll++;

            if (count($chunk) >= $flushEvery) {
                $this->queue->sendMessages($chunk);
                $chunk = [];
            }

            if ($config->signalInterval > 0 && $sincePoll >= $config->signalInterval) {
                $sincePoll = 0;
                $stream->cancellation?->offer($this->queue->peekForCancelSignal($messageId));
            }
        }

        if ($chunk !== []) {
            $this->queue->sendMessages($chunk);
        }
    }
}
