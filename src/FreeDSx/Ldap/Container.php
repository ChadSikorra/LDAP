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

namespace FreeDSx\Ldap;

use FreeDSx\Ldap\Container\ClientContainerProvider;
use FreeDSx\Ldap\Container\ConnectionGraphContainerProvider;
use FreeDSx\Ldap\Container\ContainerProviderInterface;
use FreeDSx\Ldap\Container\CoreServerContainerProvider;
use FreeDSx\Ldap\Container\PasswordPolicyContainerProvider;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;

use function in_array;

class Container
{
    /**
     * These are classes that should never cache an instance when retrieved from the container.
     */
    private const FACTORY_ONLY = [
        HandlerFactoryInterface::class,
        ServerAuthorization::class,
    ];

    /**
     * @var array<class-string, callable(self): object>
     */
    private array $instanceFactory = [];

    /**
     * @var array<class-string, object>
     */
    private array $instances = [];

    /**
     * @param array<class-string, object> $instances
     */
    public function __construct(array $instances)
    {
        foreach ($instances as $className => $instance) {
            $this->instances[$className] = $instance;
        }

        foreach ($this->providers() as $provider) {
            foreach ($provider->factories() as $className => $factory) {
                $this->registerFactory(
                    $className,
                    $factory,
                );
            }
        }
    }

    /**
     * @template T of object
     * @param class-string<T> $className
     * @return T
     */
    public function get(string $className): object
    {
        if (isset($this->instances[$className]) && $this->instances[$className] instanceof $className) {
            return $this->instances[$className];
        }

        if (!isset($this->instanceFactory[$className])) {
            throw new RuntimeException(sprintf(
                'The class "%s" is not recognized.',
                $className,
            ));
        }

        $instance = ($this->instanceFactory[$className])($this);
        if (!$instance instanceof $className) {
            throw new RuntimeException(sprintf(
                'The factory for "%s" did not return the expected type.',
                $className,
            ));
        }

        if (!in_array($className, self::FACTORY_ONLY, true)) {
            $this->instances[$className] = $instance;
        }

        return $instance;
    }

    /**
     * @param class-string $className
     */
    public function has(string $className): bool
    {
        return isset($this->instances[$className])
            || isset($this->instanceFactory[$className]);
    }

    /**
     * The providers whose factories apply to the seeded options (client and/or server).
     *
     * @return ContainerProviderInterface[]
     */
    private function providers(): array
    {
        $providers = [];

        if (isset($this->instances[ClientOptions::class])) {
            $providers[] = new ClientContainerProvider();
        }

        if (isset($this->instances[ServerOptions::class])) {
            $providers[] = new CoreServerContainerProvider();
            $providers[] = new PasswordPolicyContainerProvider();
            $providers[] = new ConnectionGraphContainerProvider();
        }

        return $providers;
    }

    /**
     * @param class-string $className
     * @param callable(self): object $factory
     */
    private function registerFactory(
        string $className,
        callable $factory,
    ): void {
        $this->instanceFactory[$className] = $factory;
    }
}
