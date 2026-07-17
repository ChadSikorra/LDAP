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

namespace FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerProtocolHandlerInterface;
use FreeDSx\Ldap\Server\SearchLimits;

/**
 * Routes a request to its protocol handler; construction is delegated to the per-route factory map.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ProtocolHandlerProvider implements ProtocolHandlerProviderInterface
{
    public function __construct(
        private HandlerRouteResolverInterface $routeResolver,
        private ProtocolHandlerFactoryMap $factories,
        private HandlerContext $context,
    ) {}

    public function get(
        RequestInterface $request,
        ControlBag $controls,
        ?SearchLimits $searchLimits = null,
    ): ServerProtocolHandlerInterface {
        return $this->factories->make(
            $this->routeResolver->routeIdFor(
                $request,
                $controls,
            ),
            $this->context,
            $searchLimits,
        );
    }
}
