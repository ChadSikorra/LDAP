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
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\Response\MetricsResponseInterceptor;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\AssertionEvaluator;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\Rollup\OperationRollupCoordinator;
use FreeDSx\Ldap\Server\Middleware\AssertionMiddleware;
use FreeDSx\Ldap\Server\Middleware\CriticalControlMiddleware;
use FreeDSx\Ldap\Server\Middleware\MetricsMiddleware;
use FreeDSx\Ldap\Server\Middleware\OperationAuthorizationMiddleware;
use FreeDSx\Ldap\Server\Middleware\ResourceLimitMiddleware;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\BindStrategy\EntryBindStrategy;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\BindStrategy\PasswordPolicyBindStrategyInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\BindStrategy\ReplicaBindStrategy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;
use FreeDSx\Ldap\Server\ConnectionHandlerBuilder;
use FreeDSx\Ldap\Server\ConnectionHandlerBuilderInterface;
use FreeDSx\Ldap\Server\SearchLimit\SearchLimitResolver;
use FreeDSx\Ldap\ServerOptions;

/**
 * Registers the connection-independent collaborators the per-connection graph composes: stateless middleware,
 * response interceptors, the bind strategy, and search-limit resolution.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ConnectionGraphContainerProvider implements ContainerProviderInterface
{
    public function factories(): array
    {
        return [
            ConnectionHandlerBuilderInterface::class => static fn(Container $container): ConnectionHandlerBuilder => new ConnectionHandlerBuilder($container),
            PasswordPolicyBindStrategyInterface::class => $this->makeBindStrategy(...),
            SearchLimitResolver::class => $this->makeSearchLimitResolver(...),
            AssertionEvaluator::class => $this->makeAssertionEvaluator(...),
            MetricsResponseInterceptor::class => $this->makeMetricsResponseInterceptor(...),
            MetricsMiddleware::class => $this->makeMetricsMiddleware(...),
            CriticalControlMiddleware::class => $this->makeCriticalControlMiddleware(...),
            OperationAuthorizationMiddleware::class => $this->makeOperationAuthorizationMiddleware(...),
            AssertionMiddleware::class => $this->makeAssertionMiddleware(...),
            ResourceLimitMiddleware::class => $this->makeResourceLimitMiddleware(...),
        ];
    }

    /**
     * The pre-bind strategy: replica-local worst-outcome state on a read-only replica, authoritative entry state otherwise.
     *
     * @throws RuntimeException when the backend cannot record password-policy bind state.
     */
    private function makeBindStrategy(Container $container): PasswordPolicyBindStrategyInterface
    {
        $engine = $container->get(PasswordPolicyEngine::class);

        if ($container->get(ServerOptions::class)->isReadOnly()) {
            return new ReplicaBindStrategy(
                $engine,
                $container->get(ReplicaPasswordStateStoreInterface::class),
            );
        }

        $backend = $container->get(HandlerFactoryInterface::class)->makeBackend();
        if (!$backend instanceof WritableLdapBackendInterface) {
            throw new RuntimeException(
                'A backend implementing WritableLdapBackendInterface is required to record password-policy bind state.',
            );
        }

        return new EntryBindStrategy(
            $engine,
            $backend,
        );
    }

    private function makeSearchLimitResolver(Container $container): SearchLimitResolver
    {
        $options = $container->get(ServerOptions::class);
        $resolver = new SearchLimitResolver(
            $options->getSearchLimitRules(),
            $options->makeSearchLimits(),
        );
        $resolver->setBackend($container->get(HandlerFactoryInterface::class)->makeBackend());

        return $resolver;
    }

    private function makeAssertionEvaluator(Container $container): AssertionEvaluator
    {
        return new AssertionEvaluator(
            $container->get(ServerOptions::class)->getFilterEvaluator(),
            $container->get(HandlerFactoryInterface::class)->makeBackend(),
        );
    }

    private function makeMetricsResponseInterceptor(Container $container): MetricsResponseInterceptor
    {
        return new MetricsResponseInterceptor($container->get(MetricsRecorderInterface::class));
    }

    private function makeMetricsMiddleware(Container $container): MetricsMiddleware
    {
        $options = $container->get(ServerOptions::class);

        return new MetricsMiddleware(
            $container->get(MetricsRecorderInterface::class),
            $options->isMonitorEnabled()
                ? $container->get(OperationRollupCoordinator::class)
                : null,
        );
    }

    private function makeCriticalControlMiddleware(Container $container): CriticalControlMiddleware
    {
        return new CriticalControlMiddleware($container->get(ServerProtocolHandlerFactory::class));
    }

    private function makeOperationAuthorizationMiddleware(Container $container): OperationAuthorizationMiddleware
    {
        $options = $container->get(ServerOptions::class);

        return new OperationAuthorizationMiddleware(
            $container->get(ServerProtocolHandlerFactory::class),
            $options->getAccessControl(),
            $options->getPrivilegedControls(),
            $options->getPrivilegedExtendedOps(),
        );
    }

    private function makeAssertionMiddleware(Container $container): AssertionMiddleware
    {
        return new AssertionMiddleware($container->get(AssertionEvaluator::class));
    }

    private function makeResourceLimitMiddleware(Container $container): ResourceLimitMiddleware
    {
        return new ResourceLimitMiddleware($container->get(SearchLimitResolver::class));
    }
}
