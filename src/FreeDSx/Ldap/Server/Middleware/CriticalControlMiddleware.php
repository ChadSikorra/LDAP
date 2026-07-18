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

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\HandlerRouteResolverInterface;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;

use function in_array;
use function sprintf;

/**
 * Rejects requests carrying a critical control the resolved handler does not support (RFC 4511 §4.1.11).
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class CriticalControlMiddleware implements MiddlewareInterface
{
    public function __construct(
        private HandlerRouteResolverInterface $routeResolver,
        private ServerControlRegistry $controlRegistry = new ServerControlRegistry(),
    ) {}

    /**
     * @throws OperationException
     */
    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): ResponseStream {
        $controls = $context->message->controls();
        $routeId = $this->routeResolver->routeIdFor(
            $context->message->getRequest(),
            $controls,
        );

        if ($this->controlRegistry->appliesTo($routeId)) {
            $this->assertNoCriticalUnsupportedControls(
                $controls,
                $this->controlRegistry->supportedControlsFor($routeId),
            );
        }

        return $next->handle($context);
    }

    /**
     * @param list<string> $supported
     * @throws OperationException
     */
    private function assertNoCriticalUnsupportedControls(
        ControlBag $controls,
        array $supported,
    ): void {
        foreach ($controls as $control) {
            if (!$control->getCriticality()) {
                continue;
            }

            if (!in_array($control->getTypeOid(), $supported, true)) {
                throw new OperationException(
                    sprintf('Critical control %s is not supported.', $control->getTypeOid()),
                    ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
                );
            }
        }
    }
}
