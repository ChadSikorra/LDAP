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

use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Protocol\Authenticator;
use FreeDSx\Ldap\Protocol\Authorization\DispatchAuthorizer;
use FreeDSx\Ldap\Protocol\Bind\SimpleBind;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerStartTlsHandler;
use FreeDSx\Ldap\ProxyOptions;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\ServerConnectionScaffoldingTrait;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Socket;

/**
 * Builds a per-connection protocol handler that forwards operations to an upstream LDAP server.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ProxyProtocolFactory implements ServerProtocolFactoryInterface
{
    use ServerConnectionScaffoldingTrait;

    public function __construct(
        private readonly ServerOptions $options,
        private readonly ProxyOptions $proxyOptions,
    ) {}

    protected function serverOptions(): ServerOptions
    {
        return $this->options;
    }

    public function make(
        Socket $socket,
        ConnectionContext $context = new ConnectionContext(),
    ): ServerProtocolHandler {
        $queue = $this->makeServerQueue($socket);
        $eventLogger = $this->makeEventLogger($context);
        $upstream = new LdapClient($this->proxyOptions->getClientOptions());
        $serverAuthorization = new ServerAuthorization($this->options);

        $authenticators = [
            new SimpleBind(
                queue: $queue,
                authenticator: new ProxyAuthenticator(
                    $upstream,
                    $this->proxyOptions->getUseStartTls(),
                ),
                eventLogger: $eventLogger,
            ),
            $this->makeAnonymousBind(
                $queue,
                $eventLogger,
            ),
        ];

        $pipeline = new ProxyRequestPipeline(
            new ServerStartTlsHandler(
                $this->options,
                $queue,
                $eventLogger,
            ),
            new ProxyRequestForwarder(
                $upstream,
                $queue,
            ),
        );

        return new ServerProtocolHandler(
            queue: $queue,
            requestPipeline: $pipeline,
            authorizer: $serverAuthorization,
            authenticator: new Authenticator($authenticators),
            dispatchAuthorizer: new DispatchAuthorizer($serverAuthorization),
            eventLogger: $eventLogger,
            connectionContext: $context,
        );
    }
}
