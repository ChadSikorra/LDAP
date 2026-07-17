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

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerProtocolHandlerInterface;
use FreeDSx\Ldap\Server\SearchLimits;

use function sprintf;

/**
 * A per-route handler factory keyed by HandlerId value; each factory finishes construction from a HandlerContext.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ProtocolHandlerFactoryMap
{
    /**
     * @param array<string, callable(HandlerContext, ?SearchLimits): ServerProtocolHandlerInterface> $factories keyed by HandlerId value.
     */
    public function __construct(private array $factories) {}

    /**
     * @throws RuntimeException when the route has no registered factory.
     */
    public function make(
        HandlerId $handlerId,
        HandlerContext $context,
        ?SearchLimits $searchLimits = null,
    ): ServerProtocolHandlerInterface {
        $factory = $this->factories[$handlerId->value]
            ?? throw new RuntimeException(sprintf(
                'No handler factory is registered for the "%s" route.',
                $handlerId->value,
            ));

        return $factory(
            $context,
            $searchLimits,
        );
    }
}
