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
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Read\ChangeStream;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Clock\BlockingSleeper;
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
use FreeDSx\Ldap\Sync\Provider\SyncPersistStreamer;
use FreeDSx\Ldap\Sync\Provider\SyncResultProjector;

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
            HandlerId::Sync => $this->getSyncHandler($searchLimits),
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

    private function getSyncHandler(?SearchLimits $searchLimits): ServerProtocolHandler\ServerSyncHandler
    {
        $backend = $this->handlerFactory->makeBackend();
        $journal = $this->syncJournalFor($backend);
        $projector = new SyncResultProjector(
            accessControl: $this->options->getAccessControl(),
            filterEvaluator: $this->options->getFilterEvaluator(),
            eventLogger: $this->eventLogger,
        );

        $stream = null;
        $streamer = null;
        $persistSupported = false;

        if ($journal !== null) {
            $stream = new ChangeStream($journal);
            $streamer = new SyncPersistStreamer(
                queue: $this->queue,
                backend: $backend,
                projector: $projector,
                stream: $stream,
                sleeper: new BlockingSleeper(),
            );
            // Persist can only deliver writes made on other connections: a single process (Swoole)
            // shares them in memory, otherwise the journal itself must be cross-process.
            $persistSupported = $this->options->getUseSwooleRunner()
                || $journal->sharesAcrossProcesses();
        }

        return new ServerProtocolHandler\ServerSyncHandler(
            queue: $this->queue,
            backend: $backend,
            projector: $projector,
            limits: $searchLimits ?? $this->options->makeSearchLimits(),
            changeStream: $stream,
            persistStreamer: $streamer,
            persistSupported: $persistSupported,
        );
    }

    private function changeStreamFor(LdapBackendInterface $backend): ?ChangeStream
    {
        $journal = $this->syncJournalFor($backend);

        return $journal !== null
            ? new ChangeStream($journal)
            : null;
    }

    private function syncJournalFor(LdapBackendInterface $backend): ?ChangeJournalInterface
    {
        if (!$this->options->isSyncEnabled() || !$backend instanceof WritableStorageBackend) {
            return null;
        }

        $storage = $backend->getStorage();

        if (!$storage instanceof ChangeJournalingInterface) {
            return null;
        }

        return $storage->changeJournal();
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
        $backend = $this->handlerFactory->makeBackend();

        return new ServerProtocolHandler\ServerRootDseHandler(
            options: $this->options,
            queue: $this->queue,
            backend: $backend,
            rootDseHandler: $this->handlerFactory->makeRootDseHandler(),
            supportsSync: $this->changeStreamFor($backend) !== null,
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
