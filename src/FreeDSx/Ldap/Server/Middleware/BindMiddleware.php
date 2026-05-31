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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authenticator;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use FreeDSx\Ldap\Server\Token\AnonToken;

/**
 * Routes bind requests to the authenticator and stores the resulting token on the connection's authorization state.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class BindMiddleware implements MiddlewareInterface
{
    public function __construct(
        private ServerAuthorization $authorization,
        private Authenticator $authenticator,
    ) {}

    /**
     * @throws OperationException
     */
    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): OperationResult {
        $request = $context->message->getRequest();

        if (!$this->authorization->isAuthenticationRequest($request)) {
            return $next->handle($context);
        }

        // RFC 4511 §4.2.1: a bind discards any prior authentication; a failed bind leaves the session anonymous.
        $this->authorization->setToken(new AnonToken());

        if (!$this->authorization->isAuthenticationTypeSupported($request)) {
            throw new OperationException(
                'The requested authentication type is not supported.',
                ResultCode::AUTH_METHOD_UNSUPPORTED,
            );
        }

        $this->authorization->setToken($this->authenticator->bind($context->message));

        return OperationOutcomeResult::succeeded();
    }
}
