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

namespace FreeDSx\Ldap\Container;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Protocol\Factory\HandlerContext;
use FreeDSx\Ldap\Protocol\Factory\HandlerId;
use FreeDSx\Ldap\Protocol\Factory\ProtocolHandlerFactoryMap;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerAbandonHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerCancelHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerDispatchHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerMonitorHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerPagingHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerPasswordModifyHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerPasswordPolicyForwardHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerProtocolHandlerInterface;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerRootDseHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerSearchHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerStartTlsHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerSubschemaHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerSyncHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerUnbindHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerUnsupportedExtendedHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerWhoAmIHandler;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Read\ChangeStream;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\Metrics\MetricsSnapshotProvider;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyService;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyTargetResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyComponentFactory;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Sync\Provider\SyncPersistStreamer;
use FreeDSx\Ldap\Sync\Provider\SyncResultProjector;

/**
 * Registers the per-route handler factories; each finishes construction from a per-connection HandlerContext.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class HandlerContainerProvider implements ContainerProviderInterface
{
    public function factories(): array
    {
        return [
            ProtocolHandlerFactoryMap::class => $this->makeFactoryMap(...),
        ];
    }

    private function makeFactoryMap(Container $container): ProtocolHandlerFactoryMap
    {
        return new ProtocolHandlerFactoryMap([
            HandlerId::Abandon->value => static fn(): ServerProtocolHandlerInterface
                => new ServerAbandonHandler(),
            HandlerId::Cancel->value => static fn(HandlerContext $context): ServerProtocolHandlerInterface
                => new ServerCancelHandler($context->queue),
            HandlerId::WhoAmI->value => static fn(HandlerContext $context): ServerProtocolHandlerInterface
                => new ServerWhoAmIHandler($context->queue),
            HandlerId::PasswordModify->value => fn(HandlerContext $context): ServerProtocolHandlerInterface
                => $this->makePasswordModifyHandler($container, $context),
            HandlerId::PasswordPolicyForward->value => fn(HandlerContext $context): ServerProtocolHandlerInterface
                => $this->makeForwardHandler($container, $context),
            HandlerId::StartTls->value => static fn(HandlerContext $context): ServerProtocolHandlerInterface
                => new ServerStartTlsHandler(
                    options: $container->get(ServerOptions::class),
                    queue: $context->queue,
                    eventLogger: $context->eventLogger,
                ),
            HandlerId::UnsupportedExtended->value => static fn(HandlerContext $context): ServerProtocolHandlerInterface
                => new ServerUnsupportedExtendedHandler($context->queue),
            HandlerId::RootDse->value => fn(HandlerContext $context): ServerProtocolHandlerInterface
                => $this->makeRootDseHandler($container, $context),
            HandlerId::Subschema->value => static fn(HandlerContext $context): ServerProtocolHandlerInterface
                => new ServerSubschemaHandler(
                    options: $container->get(ServerOptions::class),
                    queue: $context->queue,
                ),
            HandlerId::Monitor->value => static fn(HandlerContext $context): ServerProtocolHandlerInterface
                => new ServerMonitorHandler(
                    options: $container->get(ServerOptions::class),
                    queue: $context->queue,
                    snapshots: $container->get(MetricsSnapshotProvider::class),
                ),
            HandlerId::Paging->value => fn(HandlerContext $context, ?SearchLimits $limits): ServerProtocolHandlerInterface
                => $this->makePagingHandler($container, $context, $limits),
            HandlerId::Sync->value => fn(HandlerContext $context, ?SearchLimits $limits): ServerProtocolHandlerInterface
                => $this->makeSyncHandler($container, $context, $limits),
            HandlerId::Search->value => fn(HandlerContext $context, ?SearchLimits $limits): ServerProtocolHandlerInterface
                => $this->makeSearchHandler($container, $context, $limits),
            HandlerId::Unbind->value => static fn(HandlerContext $context): ServerProtocolHandlerInterface
                => new ServerUnbindHandler($context->queue),
            HandlerId::Dispatch->value => fn(HandlerContext $context): ServerProtocolHandlerInterface
                => $this->makeDispatchHandler($container, $context),
        ]);
    }

    private function makePasswordModifyHandler(
        Container $container,
        HandlerContext $context,
    ): ServerPasswordModifyHandler {
        $policyComponentFactory = $container->get(PasswordPolicyComponentFactory::class);

        return new ServerPasswordModifyHandler(
            queue: $context->queue,
            service: new PasswordModifyService(
                targetResolver: $container->get(PasswordModifyTargetResolver::class),
                accessControl: $container->get(ServerOptions::class)->getAccessControl(),
                writeDispatcher: $container->get(WriteOperationDispatcher::class),
                hashService: $container->get(PasswordHashService::class),
                changeGuard: $policyComponentFactory->makeChangeGuard(
                    $context->eventLogger,
                    $context->passwordPolicyContext,
                ),
                passwordPolicyContext: $context->passwordPolicyContext,
            ),
        );
    }

    private function makeForwardHandler(
        Container $container,
        HandlerContext $context,
    ): ServerProtocolHandlerInterface {
        $backend = $container->get(HandlerFactoryInterface::class)->makeBackend();
        if (!$backend instanceof WritableLdapBackendInterface) {
            return new ServerUnsupportedExtendedHandler($context->queue);
        }

        return new ServerPasswordPolicyForwardHandler(
            queue: $context->queue,
            backend: $backend,
            policyResolver: $container->get(PasswordPolicyComponentFactory::class)->makeResolver(),
            engine: $container->get(PasswordPolicyEngine::class),
        );
    }

    private function makeRootDseHandler(
        Container $container,
        HandlerContext $context,
    ): ServerRootDseHandler {
        $handlerFactory = $container->get(HandlerFactoryInterface::class);
        $backend = $handlerFactory->makeBackend();

        return new ServerRootDseHandler(
            options: $container->get(ServerOptions::class),
            queue: $context->queue,
            backend: $backend,
            rootDseHandler: $handlerFactory->makeRootDseHandler(),
            supportsSync: $this->syncJournalFor($container, $backend) !== null,
        );
    }

    private function makeSyncHandler(
        Container $container,
        HandlerContext $context,
        ?SearchLimits $searchLimits,
    ): ServerSyncHandler {
        $options = $container->get(ServerOptions::class);
        $backend = $container->get(HandlerFactoryInterface::class)->makeBackend();
        $journal = $this->syncJournalFor($container, $backend);
        $projector = new SyncResultProjector(
            accessControl: $options->getAccessControl(),
            filterEvaluator: $options->getFilterEvaluator(),
            eventLogger: $context->eventLogger,
        );

        $stream = null;
        $streamer = null;
        $persistSupported = false;

        if ($journal !== null) {
            $stream = new ChangeStream($journal);
            $streamer = new SyncPersistStreamer(
                queue: $context->queue,
                backend: $backend,
                projector: $projector,
                stream: $stream,
                sleeper: $container->get(SleeperInterface::class),
            );
            // Persist can only deliver writes made on other connections: a single process (Swoole)
            // shares them in memory, otherwise the journal itself must be cross-process.
            $persistSupported = $options->getUseSwooleRunner()
                || $journal->sharesAcrossProcesses();
        }

        return new ServerSyncHandler(
            queue: $context->queue,
            backend: $backend,
            projector: $projector,
            limits: $searchLimits ?? $options->makeSearchLimits(),
            changeStream: $stream,
            persistStreamer: $streamer,
            persistSupported: $persistSupported,
        );
    }

    private function makeDispatchHandler(
        Container $container,
        HandlerContext $context,
    ): ServerDispatchHandler {
        $handlerFactory = $container->get(HandlerFactoryInterface::class);
        $policyWriteHandler = $container->get(PasswordPolicyComponentFactory::class)->makeWriteHandler(
            $context->eventLogger,
            $context->passwordPolicyContext,
        );

        return new ServerDispatchHandler(
            queue: $context->queue,
            backend: $handlerFactory->makeBackend(),
            writeDispatcher: $policyWriteHandler !== null
                ? $handlerFactory->makeWriteDispatcher($policyWriteHandler)
                : $container->get(WriteOperationDispatcher::class),
            accessControl: $container->get(ServerOptions::class)->getAccessControl(),
            schema: $container->get(ServerOptions::class)->getSchema(),
        );
    }

    private function makeSearchHandler(
        Container $container,
        HandlerContext $context,
        ?SearchLimits $searchLimits,
    ): ServerSearchHandler {
        $options = $container->get(ServerOptions::class);

        return new ServerSearchHandler(
            queue: $context->queue,
            backend: $container->get(HandlerFactoryInterface::class)->makeBackend(),
            filterEvaluator: $options->getFilterEvaluator(),
            accessControl: $options->getAccessControl(),
            schema: $options->getSchema(),
            limits: $searchLimits ?? $options->makeSearchLimits(),
        );
    }

    private function makePagingHandler(
        Container $container,
        HandlerContext $context,
        ?SearchLimits $searchLimits,
    ): ServerPagingHandler {
        $options = $container->get(ServerOptions::class);

        return new ServerPagingHandler(
            queue: $context->queue,
            backend: $container->get(HandlerFactoryInterface::class)->makeBackend(),
            filterEvaluator: $options->getFilterEvaluator(),
            accessControl: $options->getAccessControl(),
            requestHistory: $context->requestHistory,
            schema: $options->getSchema(),
            limits: $searchLimits ?? $options->makeSearchLimits(),
        );
    }

    private function syncJournalFor(
        Container $container,
        LdapBackendInterface $backend,
    ): ?ChangeJournalInterface {
        if (!$container->get(ServerOptions::class)->isSyncEnabled() || !$backend instanceof WritableStorageBackend) {
            return null;
        }

        return $backend->changeJournal();
    }
}
