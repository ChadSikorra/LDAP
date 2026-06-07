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
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerProtocolHandlerInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Metrics\MetricsSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyService;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyTargetResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyComponentFactory;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\RequestHistory;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\ServerOptions;

/**
 * Builds the per-request protocol handler, wiring per-connection state to shared services.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ProtocolHandlerProvider implements ProtocolHandlerProviderInterface
{
    public function __construct(
        private HandlerRouteResolverInterface $routeResolver,
        private HandlerFactoryInterface $handlerFactory,
        private ServerOptions $options,
        private PasswordModifyTargetResolver $targetResolver,
        private PasswordHashService $hashService,
        private WriteOperationDispatcher $writeDispatcher,
        private PasswordPolicyComponentFactory $policyComponentFactory,
        private ServerQueue $queue,
        private EventLogger $eventLogger,
        private RequestHistory $requestHistory,
        private ?PasswordPolicyContext $passwordPolicyContext = null,
        private MetricsSnapshotProvider $metricsSnapshots = new InMemoryMetricsRecorder(),
    ) {}

    public function get(
        RequestInterface $request,
        ControlBag $controls,
        ?SearchLimits $searchLimits = null,
    ): ServerProtocolHandlerInterface {
        return match ($this->routeResolver->routeIdFor($request, $controls)) {
            HandlerId::Abandon => new ServerProtocolHandler\ServerAbandonHandler(),
            HandlerId::Cancel => new ServerProtocolHandler\ServerCancelHandler($this->queue),
            HandlerId::WhoAmI => new ServerProtocolHandler\ServerWhoAmIHandler($this->queue),
            HandlerId::PasswordModify => $this->getPasswordModifyHandler(),
            HandlerId::StartTls => $this->getStartTlsHandler(),
            HandlerId::UnsupportedExtended => new ServerProtocolHandler\ServerUnsupportedExtendedHandler($this->queue),
            HandlerId::RootDse => $this->getRootDseHandler(),
            HandlerId::Subschema => $this->getSubschemaHandler(),
            HandlerId::Monitor => $this->getMonitorHandler(),
            HandlerId::Paging => $this->getPagingHandler($searchLimits),
            HandlerId::Search => $this->getSearchHandler($searchLimits),
            HandlerId::Unbind => new ServerProtocolHandler\ServerUnbindHandler($this->queue),
            HandlerId::Dispatch => $this->getDispatchHandler(),
        };
    }

    private function getPasswordModifyHandler(): ServerProtocolHandler\ServerPasswordModifyHandler
    {
        return new ServerProtocolHandler\ServerPasswordModifyHandler(
            queue: $this->queue,
            service: new PasswordModifyService(
                targetResolver: $this->targetResolver,
                accessControl: $this->options->getAccessControl(),
                writeDispatcher: $this->writeDispatcher,
                hashService: $this->hashService,
                changeGuard: $this->policyComponentFactory->makeChangeGuard(
                    $this->eventLogger,
                    $this->passwordPolicyContext,
                ),
                passwordPolicyContext: $this->passwordPolicyContext,
            ),
        );
    }

    private function getStartTlsHandler(): ServerProtocolHandler\ServerStartTlsHandler
    {
        return new ServerProtocolHandler\ServerStartTlsHandler(
            options: $this->options,
            queue: $this->queue,
            eventLogger: $this->eventLogger,
        );
    }

    private function getSubschemaHandler(): ServerProtocolHandler\ServerSubschemaHandler
    {
        return new ServerProtocolHandler\ServerSubschemaHandler(
            options: $this->options,
            queue: $this->queue,
        );
    }

    private function getMonitorHandler(): ServerProtocolHandler\ServerMonitorHandler
    {
        return new ServerProtocolHandler\ServerMonitorHandler(
            options: $this->options,
            queue: $this->queue,
            snapshots: $this->metricsSnapshots,
        );
    }

    private function getSearchHandler(?SearchLimits $searchLimits): ServerProtocolHandler\ServerSearchHandler
    {
        return new ServerProtocolHandler\ServerSearchHandler(
            queue: $this->queue,
            backend: $this->handlerFactory->makeBackend(),
            filterEvaluator: $this->options->getFilterEvaluator(),
            accessControl: $this->options->getAccessControl(),
            schema: $this->options->getSchema(),
            limits: $searchLimits ?? $this->options->makeSearchLimits(),
        );
    }

    private function getDispatchHandler(): ServerProtocolHandler\ServerDispatchHandler
    {
        $policyWriteHandler = $this->policyComponentFactory->makeWriteHandler(
            $this->eventLogger,
            $this->passwordPolicyContext,
        );

        return new ServerProtocolHandler\ServerDispatchHandler(
            queue: $this->queue,
            backend: $this->handlerFactory->makeBackend(),
            writeDispatcher: $policyWriteHandler !== null
                ? $this->handlerFactory->makeWriteDispatcher($policyWriteHandler)
                : $this->writeDispatcher,
            accessControl: $this->options->getAccessControl(),
            schema: $this->options->getSchema(),
        );
    }

    private function getRootDseHandler(): ServerProtocolHandler\ServerRootDseHandler
    {
        return new ServerProtocolHandler\ServerRootDseHandler(
            options: $this->options,
            queue: $this->queue,
            backend: $this->handlerFactory->makeBackend(),
            rootDseHandler: $this->handlerFactory->makeRootDseHandler(),
        );
    }

    private function getPagingHandler(?SearchLimits $searchLimits): ServerProtocolHandler\ServerPagingHandler
    {
        return new ServerProtocolHandler\ServerPagingHandler(
            queue: $this->queue,
            backend: $this->handlerFactory->makeBackend(),
            filterEvaluator: $this->options->getFilterEvaluator(),
            accessControl: $this->options->getAccessControl(),
            requestHistory: $this->requestHistory,
            schema: $this->options->getSchema(),
            limits: $searchLimits ?? $this->options->makeSearchLimits(),
        );
    }
}
