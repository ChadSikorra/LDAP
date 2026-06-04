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

namespace FreeDSx\Ldap\Server\Proxy;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Operation\OperationResult;

/**
 * Relays a request to the upstream connection and relays the response back to the client.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ProxyRequestForwarder implements MiddlewareHandlerInterface
{
    public function __construct(
        private LdapClient $client,
        private ServerQueue $queue,
        private ResponseFactory $responseFactory = new ResponseFactory(),
    ) {}

    /**
     * {@inheritDoc}
     */
    public function handle(ServerRequestContext $context): OperationResult
    {
        $message = $context->message;
        $request = $message->getRequest();

        if ($request instanceof UnbindRequest) {
            $this->client->unbind();
            $this->queue->close();

            return OperationOutcomeResult::succeeded();
        }

        // Synchronous, sequential forwarding means nothing is ever in flight upstream to abandon.
        if ($request instanceof AbandonRequest) {
            return OperationOutcomeResult::succeeded();
        }

        try {
            $response = $this->sendUpstream(
                $request,
                $message->controls()->toArray(),
            );
        } catch (OperationException $e) {
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                $e->getCode(),
                $e->getMessage(),
                $e->getMatchedDn(),
            ));

            return OperationOutcomeResult::failed($e->getCode());
        }

        if ($request instanceof SearchRequest) {
            $this->relaySearch($message, $response);
        } else {
            $this->relaySingle($message, $response);
        }

        return OperationOutcomeResult::succeeded();
    }

    /**
     * @param array<int, Control> $controls
     * @throws OperationException
     */
    private function sendUpstream(
        RequestInterface $request,
        array $controls,
    ): LdapMessageResponse {
        try {
            return $this->client->sendAndReceive(
                $request,
                ...$controls,
            );
        } catch (ConnectionException) {
            throw new OperationException(
                'The upstream LDAP server is unavailable.',
                ResultCode::UNAVAILABLE,
            );
        }
    }

    private function relaySingle(
        LdapMessageRequest $message,
        LdapMessageResponse $response,
    ): void {
        $this->queue->sendMessage(new LdapMessageResponse(
            $message->getMessageId(),
            $response->getResponse(),
            ...$response->controls()->toArray(),
        ));
    }

    private function relaySearch(
        LdapMessageRequest $message,
        LdapMessageResponse $response,
    ): void {
        $searchResponse = $response->getResponse();

        if (!$searchResponse instanceof SearchResponse) {
            $this->relaySingle($message, $response);

            return;
        }

        $messageId = $message->getMessageId();
        $messages = [];

        foreach ($searchResponse->getEntries() as $entry) {
            $messages[] = new LdapMessageResponse(
                $messageId,
                new SearchResultEntry($entry),
            );
        }

        $messages[] = new LdapMessageResponse(
            $messageId,
            new SearchResultDone(
                $searchResponse->getResultCode(),
                $searchResponse->getDn(),
                $searchResponse->getDiagnosticMessage(),
            ),
            ...$response->controls()->toArray(),
        );

        $this->queue->sendMessages($messages);
    }
}
