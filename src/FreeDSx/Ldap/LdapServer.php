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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\LdifParseException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Ldif\LdifParser;
use FreeDSx\Ldap\Ldif\Loader\LdifLoaderInterface;
use FreeDSx\Ldap\Ldif\Output\LdifOutputInterface;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\BackendAwareInterface;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Storage\OperationalAttributeGenerator;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Export\DirectoryDumper;
use FreeDSx\Ldap\Server\Backend\Storage\Export\DumpOptions;
use FreeDSx\Ldap\Server\Backend\Storage\LdapImporter;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestReplayer;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Socket\Exception\ConnectionException;
use Generator;
use Psr\Log\LoggerInterface;

/**
 * The LDAP server.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapServer
{
    private Container $container;

    private ?AccessControlInterface $accessControl = null;

    public function __construct(
        private readonly ServerOptions $options = new ServerOptions(),
        ?Container $container = null,
    ) {
        $this->container = $container ?? new Container([
            ServerOptions::class => $this->options,
        ]);
    }

    /**
     * Runs the LDAP server. Binds the socket and starts accepting client connections.
     *
     * @throws ConnectionException
     */
    public function run(): void
    {
        $this->init();

        $runner = $this->options->getServerRunner() ?? $this->container->get(ServerRunnerInterface::class);

        $runner->run();
    }

    /**
     * Specify a fully custom access control implementation; rare — prefer ServerOptions rules instead.
     */
    public function useAccessControl(AccessControlInterface $acl): self
    {
        $this->accessControl = $acl;

        return $this;
    }

    private function init(): void
    {
        $this->options->setAccessControl($this->resolveAccessControl());
    }

    private function resolveAccessControl(): AccessControlInterface
    {
        if ($this->accessControl !== null) {
            return $this->injectBackendIfNeeded($this->accessControl);
        }

        $aclRules = $this->options->getAclRules();

        if ($aclRules->isEmpty()) {
            return $this->options->getAccessControl();
        }

        return $this->injectBackendIfNeeded(new RuleBasedAccessControl($aclRules));
    }

    private function injectBackendIfNeeded(AccessControlInterface $acl): AccessControlInterface
    {
        $backend = $this->options->getBackend();

        if ($backend !== null && $acl instanceof BackendAwareInterface) {
            $acl->setBackend($backend);
        }

        return $acl;
    }

    /**
     * Get the options currently set for the LDAP server.
     */
    public function getOptions(): ServerOptions
    {
        return $this->options;
    }

    /**
     * Specify an entry storage implementation to back the LDAP server.
     *
     * Schema validation is applied automatically. If you don't want it, set {@see SchemaValidationMode::Off} in your
     * server options.
     *
     * Use {@see useBackend()} instead when implementing a fully custom backend (e.g. a proxy) that handles LDAP
     * semantics itself.
     */
    public function useStorage(EntryStorageInterface $storage): self
    {
        $schema = $this->options->getSchemaValidationMode() !== SchemaValidationMode::Off
            ? $this->options->getSchema()
            : null;

        return $this->useBackend(new WritableStorageBackend(
            storage: $storage,
            limits: $this->options->makeSearchLimits(),
            validator: $this->buildSchemaValidator(),
            operationalAttrs: new OperationalAttributeGenerator($schema),
        ));
    }

    /**
     * Bulk-loads LDIF content records into the storage configured via {@see useStorage()} as one atomic batch.
     *
     * Use {@see applyChanges()} instead to replay a changelog (modify/delete/rename) through the live write path.
     *
     * @param Dn $creatorDn DN recorded as creatorsName/modifiersName on imported entries; defaults to the anonymous (empty) DN.
     * @throws LdifParseException when the LDIF cannot be parsed
     * @throws RuntimeException when no storage backend is configured (or the loader fails to load)
     * @throws InvalidArgumentException when the creator DN is malformed or an entry's parent is missing
     * @throws OperationException when an entry violates the schema and validation mode is strict
     */
    public function seed(
        LdifLoaderInterface $loader,
        Dn $creatorDn = new Dn(''),
    ): self {
        $backend = $this->options->getBackend();

        if (!$backend instanceof WritableStorageBackend) {
            throw new RuntimeException('seed() requires a storage backend configured via useStorage().');
        }

        (new LdapImporter(
            $backend->getStorage(),
            $backend->getOperationalAttributeGenerator(),
            $backend->getSchemaValidator(),
            $creatorDn,
        ))->importEntries($this->streamSeedEntries($loader));

        return $this;
    }

    /**
     * @return Generator<Entry>
     * @throws RuntimeException when the LDIF contains a non-add change record
     * @throws LdifParseException
     */
    private function streamSeedEntries(LdifLoaderInterface $loader): Generator
    {
        foreach ((new LdifParser())->parse($loader) as $request) {
            if (!$request instanceof AddRequest) {
                throw new RuntimeException(
                    'seed() only accepts content records (adds). Use applyChanges() for modify/delete/rename.',
                );
            }

            yield $request->getEntry();
        }
    }

    /**
     * Replays an LDIF changelog against the configured backend via the live write path.
     *
     * Use {@see seed()} instead for bulk initial provisioning of content records straight to storage.
     *
     * @throws LdifParseException when the LDIF cannot be parsed
     * @throws RuntimeException when no writable backend is configured
     * @throws OperationException when a write fails (no such entry, schema violation, etc.)
     */
    public function applyChanges(LdifLoaderInterface $loader): self
    {
        $backend = $this->options->getBackend();

        if (!$backend instanceof WriteHandlerInterface) {
            throw new RuntimeException('applyChanges() requires a writable backend.');
        }

        (new WriteRequestReplayer(
            $backend,
            $this->options->getWriteHandlers(),
        ))->apply((new LdifParser())->parse($loader));

        return $this;
    }

    /**
     * Streams the configured storage backend's entries as RFC 2849 LDIF content records to the given output.
     *
     * Symmetric with {@see seed()}: the produced LDIF re-seeds the directory verbatim, including operational
     * attributes.
     *
     * @throws RuntimeException when no storage backend is configured
     */
    public function dump(
        LdifOutputInterface $output,
        DumpOptions $options = new DumpOptions(),
    ): self {
        $backend = $this->options->getBackend();

        if (!$backend instanceof WritableStorageBackend) {
            throw new RuntimeException('dump() requires a storage backend configured via useStorage().');
        }

        $output->write((new DirectoryDumper(
            $backend,
            $backend->namingContexts(),
            $this->options->getFilterEvaluator(),
        ))->dump($options));

        return $this;
    }

    private function buildSchemaValidator(): ?SchemaValidator
    {
        $mode = $this->options->getSchemaValidationMode();

        if ($mode === SchemaValidationMode::Off) {
            return null;
        }

        return new SchemaValidator(
            $this->options->getSchema(),
            $mode,
        );
    }

    /**
     * Specify a backend to use for incoming LDAP requests.
     */
    public function useBackend(LdapBackendInterface $backend): self
    {
        $this->options->setBackend($backend);

        return $this;
    }

    /**
     * Set the identity resolver used to translate a name to an Entry for simple bind, SASL bind, and PasswordModify.
     */
    public function useIdentityResolver(BindNameResolverInterface $resolver): self
    {
        $this->options->setIdentityResolver($resolver);

        return $this;
    }

    /**
     * Override the password authenticator used for simple bind and SASL PLAIN.
     */
    public function usePasswordAuthenticator(PasswordAuthenticatableInterface $authenticator): self
    {
        $this->options->setPasswordAuthenticator($authenticator);

        return $this;
    }

    /**
     * Register a handler for one or more LDAP write operations.
     */
    public function useWriteHandler(WriteHandlerInterface $handler): self
    {
        $this->options->addWriteHandler($handler);

        return $this;
    }

    /**
     * Specify an instance of a RootDSE handler to use for RootDSE requests.
     */
    public function useRootDseHandler(RootDseHandlerInterface $rootDseHandler): self
    {
        $this->options->setRootDseHandler($rootDseHandler);

        return $this;
    }

    /**
     * Override the filter evaluator used by the server when applying LDAP filters
     * to entries returned by the backend's search() generator.
     */
    public function useFilterEvaluator(FilterEvaluatorInterface $evaluator): self
    {
        $this->options->setFilterEvaluator($evaluator);

        return $this;
    }

    /**
     * Specify a logger to be used by the server process.
     */
    public function useLogger(LoggerInterface $logger): self
    {
        $this->options->setLogger($logger);

        return $this;
    }

    /**
     * Configure the server to use the Swoole coroutine runner instead of the default PCNTL process runner.
     *
     * Requires the swoole PHP extension. The SwooleServerRunner handles each client connection in its own
     * coroutine within a single process, making in-memory storage adapters safe to use concurrently.
     */
    public function useSwooleRunner(): self
    {
        $this->options->setUseSwooleRunner(true);

        return $this;
    }

    /**
     * Convenience method for generating an LDAP server instance that forwards client requests to an upstream server.
     *
     * @param ProxyOptions $proxyOptions The upstream connection (set servers/TLS on its ClientOptions).
     * @param ServerOptions $serverOptions Server options for the proxy's own listener (ip/port/transport, downstream TLS).
     */
    public static function makeProxy(
        ProxyOptions $proxyOptions,
        ServerOptions $serverOptions = new ServerOptions(),
    ): LdapServer {
        return new LdapServer(
            $serverOptions,
            new Container([
                ServerOptions::class => $serverOptions,
                ProxyOptions::class => $proxyOptions,
            ]),
        );
    }
}
