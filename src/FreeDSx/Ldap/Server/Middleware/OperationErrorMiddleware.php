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

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\MatchedDnAccessFilterTrait;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Operation\OperationResult;

/**
 * Translates an OperationException thrown anywhere below into the matching response.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class OperationErrorMiddleware implements MiddlewareInterface
{
    use MatchedDnAccessFilterTrait;

    public function __construct(
        private ServerQueue $queue,
        private LdapBackendInterface $backend,
        private AccessControlInterface $accessControl,
        private ResponseFactory $responseFactory = new ResponseFactory(),
    ) {}

    /**
     * @throws EncoderException
     */
    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): OperationResult {
        try {
            return $next->handle($context);
        } catch (OperationException $e) {
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $context->message,
                $e->getCode(),
                $e->getMessage(),
                $this->filterMatchedDn(
                    $e->getMatchedDn(),
                    $context->tokenOrFail(),
                    $this->backend,
                    $this->accessControl,
                ),
            ));

            return OperationOutcomeResult::failed($e->getCode());
        }
    }
}
