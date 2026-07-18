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

namespace FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\Exception\RequestValidationException;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;

use function in_array;
use function sprintf;

/**
 * Rejects a message whose ID is zero or already used on this connection (RFC 4511 §4.1.1.1).
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class RequestValidationMiddleware implements MiddlewareInterface
{
    /**
     * @var int[]
     */
    private array $messageIds = [];

    /**
     * @throws RequestValidationException
     */
    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): ResponseStream {
        $messageId = $context->message->getMessageId();

        if ($messageId === 0) {
            throw new RequestValidationException('The message ID 0 cannot be used in a client request.');
        }

        // Stricter than RFC 4511 §4.1.1.1, which only forbids reusing an ID that is still outstanding. Since the
        // server processes a connection's messages serially, rejecting any reused ID is safe and simpler.
        if (in_array($messageId, $this->messageIds, true)) {
            throw new RequestValidationException(sprintf('The message ID %s is not valid.', $messageId));
        }

        $this->messageIds[] = $messageId;

        return $next->handle($context);
    }
}
