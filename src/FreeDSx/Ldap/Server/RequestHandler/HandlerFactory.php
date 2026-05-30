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

namespace FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\AttributeSearchBindNameResolver;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverChain;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\DnBindNameResolver;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticator;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\ServerOptions;

/**
 * This is used by the server protocol handler to instantiate the possible user-land LDAP handlers (ie. handlers exposed
 * in the public API options).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class HandlerFactory implements HandlerFactoryInterface
{
    public function __construct(private readonly ServerOptions $options) {}

    /**
     * @inheritDoc
     */
    public function makeBackend(): LdapBackendInterface
    {
        return $this->options->getBackend() ?? new WritableStorageBackend(new InMemoryStorage());
    }

    /**
     * @inheritDoc
     */
    public function makeRootDseHandler(): ?RootDseHandlerInterface
    {
        $explicit = $this->options->getRootDseHandler();
        if ($explicit !== null) {
            return $explicit;
        }

        $backend = $this->options->getBackend();
        if ($backend instanceof RootDseHandlerInterface) {
            return $backend;
        }

        return null;
    }

    /**
     * @inheritDoc
     */
    public function makePasswordAuthenticator(): PasswordAuthenticatableInterface
    {
        $explicit = $this->options->getPasswordAuthenticator();

        if ($explicit !== null) {
            return $explicit;
        }

        $backend = $this->makeBackend();

        if ($backend instanceof PasswordAuthenticatableInterface) {
            return $backend;
        }

        return new PasswordAuthenticator(
            $this->makeIdentityResolverChain(),
            $backend,
        );
    }

    public function makeIdentityResolverChain(): BindNameResolverInterface
    {
        $configured = $this->options->getIdentityResolver();

        return new BindNameResolverChain([
            new DnBindNameResolver(),
            $configured ?? new AttributeSearchBindNameResolver(),
        ]);
    }

    /**
     * @inheritDoc
     */
    public function makeWriteDispatcher(WriteHandlerInterface ...$prepend): WriteOperationDispatcher
    {
        $handlers = $this->options->getWriteHandlers();

        $backend = $this->options->getBackend();
        if ($backend !== null) {
            $handlers[] = $backend;
        }

        return new WriteOperationDispatcher(
            ...$prepend,
            ...$handlers,
        );
    }
}
