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

namespace FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Protocol\Authenticator;
use FreeDSx\Ldap\Protocol\Bind\AnonymousBind;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\MechanismOptionsBuilderFactory;
use FreeDSx\Ldap\Protocol\Bind\Sasl\SaslExchange;
use FreeDSx\Ldap\Protocol\Bind\SaslBind;
use FreeDSx\Ldap\Protocol\Bind\SimpleBind;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\SaslOptions;
use FreeDSx\Sasl\Sasl;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Socket;

class ServerProtocolFactory
{
    public function __construct(
        private readonly HandlerFactoryInterface $handlerFactory,
        private readonly ServerOptions $options,
        private readonly ServerAuthorization $serverAuthorization,
    ) {}

    public function make(
        Socket $socket,
        ConnectionContext $context = new ConnectionContext(),
    ): ServerProtocolHandler {
        $serverQueue = new ServerQueue($socket);
        $eventLogger = new EventLogger(
            $this->options->getLogger(),
            $this->options->getEventLogPolicy(),
            $context->toLogContext(),
        );

        $backend = $this->handlerFactory->makeBackend();
        $passwordAuthenticator = $this->handlerFactory->makePasswordAuthenticator();

        $authenticators = [
            new SimpleBind(
                queue: $serverQueue,
                authenticator: $passwordAuthenticator,
                eventLogger: $eventLogger,
            ),
            new AnonymousBind(
                $serverQueue,
                $eventLogger,
            ),
        ];
        $saslMechanisms = $this->options->getSaslMechanisms();

        if (!empty($saslMechanisms)) {
            $responseFactory = new ResponseFactory();
            $authenticators[] = new SaslBind(
                queue: $serverQueue,
                exchange: new SaslExchange(
                    $serverQueue,
                    $responseFactory,
                    new MechanismOptionsBuilderFactory($passwordAuthenticator),
                ),
                sasl: new Sasl(new SaslOptions(
                    supported: $this->parseKnownMechanisms($saslMechanisms),
                )),
                mechanisms: $saslMechanisms,
                responseFactory: $responseFactory,
                eventLogger: $eventLogger,
            );
        }

        return new ServerProtocolHandler(
            queue: $serverQueue,
            protocolHandlerFactory: new ServerProtocolHandlerFactory(
                handlerFactory: $this->handlerFactory,
                options: $this->options,
                requestHistory: new RequestHistory(),
                queue: $serverQueue,
                eventLogger: $eventLogger,
            ),
            authorizer: $this->serverAuthorization,
            authenticator: new Authenticator($authenticators),
            eventLogger: $eventLogger,
        );
    }

    /**
     * Converts mechanism name strings into known MechanismName values, discarding unrecognised ones.
     *
     * @param string[] $mechanisms
     * @return MechanismName[]
     */
    private function parseKnownMechanisms(array $mechanisms): array
    {
        $known = [];
        foreach ($mechanisms as $name) {
            $mech = MechanismName::tryFrom($name);
            if ($mech !== null) {
                $known[] = $mech;
            }
        }

        return $known;
    }
}
