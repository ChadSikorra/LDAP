General LDAP Server Usage
===================

* [Quick Start Scenarios](#quick-start-scenarios)
  * [In-Memory Server](#in-memory-server)
  * [File-Backed Server with Custom Bind Names](#file-backed-server-with-custom-bind-names)
  * [Challenge SASL with a Custom Authenticator](#challenge-sasl-with-a-custom-authenticator)
* [Running the Server](#running-the-server)
* [Creating a Proxy Server](#creating-a-proxy-server)
* [Providing a Backend](#providing-a-backend)
  * [Read-Only Backend](#read-only-backend)
  * [Writable Backend](#writable-backend)
  * [Built-In Storage Implementations](#built-in-storage-implementations)
    * [InMemoryStorage](#inmemorystorage)
    * [JsonFileStorage](#jsonfilestorage)
    * [SqliteStorage](#sqlitestorage)
    * [MysqlStorage](#mysqlstorage)
  * [Custom Filter Evaluation](#custom-filter-evaluation)
* [LDIF Data](#ldif-data)
  * [Seeding Initial Entries](#seeding-initial-entries)
  * [Replaying LDIF Changelogs](#replaying-ldif-changelogs)
  * [Dumping the Directory](#dumping-the-directory)
  * [Inspecting Parsed LDIF](#inspecting-parsed-ldif)
* [Authentication](#authentication)
  * [Default Authentication](#default-authentication)
  * [Custom Bind Name Resolution](#custom-bind-name-resolution)
  * [Custom Authenticator](#custom-authenticator)
* [Handling the RootDSE](#handling-the-rootdse)
* [StartTLS SSL Certificate Support](#starttls-ssl-certificate-support)
* [SASL Authentication](#sasl-authentication)
  * [PLAIN Mechanism](#plain-mechanism)
  * [Challenge-Based Mechanisms (CRAM-MD5, DIGEST-MD5, and SCRAM)](#challenge-based-mechanisms-cram-md5-digest-md5-and-scram)
  * [Identity Resolution for SASL](#identity-resolution-for-sasl)
* [Password Modify Extended Operation](#password-modify-extended-operation)

The LdapServer class runs an LDAP server process that accepts client requests and sends back responses. It defaults to
using a forking method (PCNTL) for handling client connections, which is only available on Linux.

The server has no built-in entry persistence. You provide a backend that implements the storage logic for your use
case. Authentication is a separate, independently configurable concern. See [Providing a Backend](#providing-a-backend)
and [Authentication](#authentication) for details.

## Quick Start Scenarios

### In-Memory Server

The simplest useful setup: an in-memory directory pre-seeded with entries. Ideal for testing or applications that
reconstruct the directory on each start.

The built-in `PasswordAuthenticator` handles bind authentication automatically — it reads the `userPassword` attribute
from entries and verifies credentials against it. Supported hash schemes: `{SHA}`, `{SSHA}`, `{MD5}`, `{SMD5}`, and
plaintext.

```php
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\ServerOptions;

$passwordHash = '{SHA}' . base64_encode(sha1('secret', true));

$server = new LdapServer();

$server->useStorage(new InMemoryStorage([
    new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
    new Entry(
        new Dn('cn=admin,dc=example,dc=com'),
        new Attribute('cn', 'admin'),
        new Attribute('userPassword', $passwordHash),
    ),
]));

$server->run();
```

Clients bind as `cn=admin,dc=example,dc=com` with password `secret`. No further configuration needed.

---

### File-Backed Server with Custom Bind Names

A persistent directory stored in a JSON file. Clients bind with a bare username (`alice`) instead of a full DN.
The built-in identity resolver already handles this; if the bind name is not a valid DN, it falls back to
searching for an entry where the `uid` attribute matches.

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\JsonFileStorage;
use FreeDSx\Ldap\ServerOptions;

$server = new LdapServer(
    (new ServerOptions())->setSaslMechanisms(ServerOptions::SASL_PLAIN),
);

$server->useStorage(JsonFileStorage::forPcntl('/var/lib/myapp/ldap.json'));
$server->run();
```

To use a different attribute (e.g. `mail`) or restrict the search base, configure `setIdentityResolver()` via
[configuration](Configuration.md#setidentityresolver).

---

### Challenge SASL with a Custom Authenticator

For full control over credential storage, such as delegating to an external user store or database, implement
`PasswordAuthenticatableInterface` directly. This single interface covers all bind types:

- `authenticate()` is called for simple binds
- `getSaslIdentity()` is called for all SASL mechanisms (PLAIN, CRAM-MD5, DIGEST-MD5, SCRAM-*)

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\SaslIdentity;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\JsonFileStorage;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Sasl\Mechanism\MechanismName;
use SensitiveParameter;

class MyAuthenticator implements PasswordAuthenticatableInterface
{
    public function authenticate(
        string $name,
        #[SensitiveParameter]
        string $password,
    ): AuthenticatedTokenInterface {
        // Verify against your user store — any hashing scheme works here.
    }

    public function getSaslIdentity(
        string $username,
        MechanismName $mechanism,
    ): ?SaslIdentity {
        // Challenge SASL requires a plaintext (or recoverable) password.
        // Passwords stored with one-way hashing (bcrypt, argon2) cannot be used here.
        $password = $this->lookupPlaintextPassword($username);
        $dn = $this->lookupDn($username);

        return $password !== null && $dn !== null
            ? new SaslIdentity($password, $dn)
            : null;
    }
}

$server = new LdapServer(
    (new ServerOptions())->setSaslMechanisms(
        ServerOptions::SASL_PLAIN,
        ServerOptions::SASL_SCRAM_SHA_256,
    ),
);

$server->useStorage(JsonFileStorage::forPcntl('/var/lib/myapp/ldap.json'));
$server->usePasswordAuthenticator(new MyAuthenticator());
$server->run();
```

The backend handles directory data (search, writes). The authenticator handles credentials. Neither needs to know
about the other.

---

## Running The Server

In its simplest form you construct the server and call `run()`. Without a backend configured, the server accepts
connections and returns empty results for searches; write operations are rejected with `unwillingToPerform`.

```php
use FreeDSx\Ldap\LdapServer;

$server = (new LdapServer())->run();
```

## Creating a Proxy Server

The server can act as a transparent proxy to an upstream LDAP server via `LdapServer::makeProxy()`.

**Note**: Each client connection gets its own upstream connection. Requests (with their controls) are relayed upstream and
the responses (with their controls) relayed back. So the upstream is the authority. Works on all server runners.

```php
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\ProxyOptions;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;

// The upstream connection: servers + TLS live on the ClientOptions.
$proxyOptions = new ProxyOptions(
    (new ClientOptions())
        ->setServers(['ldap.example.com'])
        // Upstream TLS: LDAPS here, or $proxyOptions->setUseStartTls(true) for StartTLS.
        ->setUseSsl(true),
);

// The proxy's own listener: port/transport + downstream TLS cert.
$serverOptions = (new ServerOptions())
    ->setPort(3389)
    ->setSslCert('/path/to/cert.pem')
    ->setSslCertKey('/path/to/key.pem');

$server = LdapServer::makeProxy(
    $proxyOptions,
    $serverOptions,
);
$server->run();
```

TLS terminates at each hop: configure the **upstream** hop on the `ClientOptions` (LDAPS via `setUseSsl`,
or `ProxyOptions::setUseStartTls(true)`), and the **downstream** hop on the `ServerOptions` (LDAPS, or a
client StartTLS upgrade using the configured server cert).

**Note**: only simple and anonymous binds are proxied (SASL is not), and every request is forwarded to the
single configured upstream.

## Providing a Backend

For storage-backed servers, provide an `EntryStorageInterface` implementation via `useStorage()`. FreeDSx LDAP
wraps it in `WritableStorageBackend`, which handles all LDAP semantics — validation, error codes, scope checking,
and entry transformation. Your storage implementation handles only raw persistence.

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;

$server = (new LdapServer())->useStorage(new InMemoryStorage($entries));
$server->run();
```

For backends that implement full LDAP semantics themselves, use `useBackend()` with a class
implementing `LdapBackendInterface` (read-only) or `WritableLdapBackendInterface` (read + write):

```php
use FreeDSx\Ldap\LdapServer;

$server = (new LdapServer())->useBackend(new MyBackend());
$server->run();
```

All client LDAP operations — search, add, delete, modify, rename, compare — are routed to the backend.
Paging is handled automatically: a PHP generator is stored per connection and resumes it for each page
request. Your `search()` implementation simply yields entries.

Authentication is a **separate concern** handled by `PasswordAuthenticatableInterface`. See [Authentication](#authentication).

### Read-Only Backend

`LdapBackendInterface` requires two methods:

```php
namespace App;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use Generator;

class MyReadOnlyBackend implements LdapBackendInterface
{
    /**
     * Return an EntryStream of candidate entries for the search.
     *
     * The FilterEvaluator runs as a final pass, so you may pre-filter for efficiency or
     * yield all entries in scope for simplicity.
     */
    public function search(
        SearchRequest $request,
        ControlBag $controls = new ControlBag(),
    ): EntryStream {
        // $request->getBaseDn()         — ?Dn: the search base
        // $request->getScope()          — int: SearchRequest::SCOPE_BASE_OBJECT | SCOPE_SINGLE_LEVEL | SCOPE_WHOLE_SUBTREE
        // $request->getFilter()         — FilterInterface: the requested LDAP filter
        // $request->getAttributes()     — Attribute[]: requested attributes (empty = all)
        // $request->getAttributesOnly() — bool: return only attribute names, not values

        return new EntryStream($this->yieldEntries());
    }

    private function yieldEntries(): Generator
    {
        yield Entry::fromArray('cn=Foo,dc=example,dc=com', ['cn' => 'Foo', 'sn' => 'Bar']);
        yield Entry::fromArray('cn=Bar,dc=example,dc=com', ['cn' => 'Bar', 'sn' => 'Baz']);
    }

    /**
     * Return a single entry by DN, or null if it does not exist.
     * Used for compare operations and bind name resolution.
     */
    public function get(Dn $dn): ?Entry
    {
        // ...
        return null;
    }

    /**
     * Return true if the attribute-value assertion matches the entry, false if not.
     * Throw OperationException(NO_SUCH_OBJECT) if the entry does not exist.
     */
    public function compare(
        Dn $dn,
        EqualityFilter $filter,
    ): bool {
        $entry = $this->get($dn);

        if ($entry === null) {
            throw new OperationException(
                sprintf('No such object: %s', $dn->toString()),
                ResultCode::NO_SUCH_OBJECT,
            );
        }

        $attribute = $entry->get($filter->getAttribute());

        return $attribute !== null && $attribute->has($filter->getValue());
    }
}
```

### Writable Backend

`WritableLdapBackendInterface` extends `LdapBackendInterface` with write operations. Use `WritableBackendTrait`
to implement the write dispatch — it routes each operation to a dedicated method receiving a typed command object:

```php
namespace App;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WritableBackendTrait;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use Generator;

class MyBackend implements WritableLdapBackendInterface
{
    use WritableBackendTrait;

    public function search(
        SearchRequest $request,
        ControlBag $controls = new ControlBag(),
    ): EntryStream {
        // Return an EntryStream wrapping a generator of matching entries...
        return new EntryStream($this->yieldNothing());
    }

    private function yieldNothing(): Generator
    {
        yield from [];
    }

    public function get(Dn $dn): ?Entry
    {
        // ...
        return null;
    }

    public function compare(
        Dn $dn,
        EqualityFilter $filter,
    ): bool {
        $entry = $this->get($dn);

        if ($entry === null) {
            throw new OperationException(
                sprintf('No such object: %s', $dn->toString()),
                ResultCode::NO_SUCH_OBJECT,
            );
        }

        $attribute = $entry->get($filter->getAttribute());

        return $attribute !== null && $attribute->has($filter->getValue());
    }

    public function add(
        AddCommand $command,
        WriteContext $context,
    ): void {
        // $command->entry        — Entry to persist
        // $context->getBoundDn() — ?string: DN of the authenticated user, or null for anonymous
    }

    public function delete(
        DeleteCommand $command,
        WriteContext $context,
    ): void {
        // $command->dn — Dn of the entry to remove
    }

    public function update(
        UpdateCommand $command,
        WriteContext $context,
    ): void {
        // $command->dn      — Dn of the entry to modify
        // $command->changes — Change[] of attribute changes to apply
    }

    public function move(
        MoveCommand $command,
        WriteContext $context,
    ): void {
        // $command->dn           — Dn: current entry DN
        // $command->newRdn       — Rdn: new relative DN
        // $command->deleteOldRdn — bool: whether to remove the old RDN attribute value
        // $command->newParent    — ?Dn: new parent DN (null = same parent)
    }
}
```

### Built-In Storage Implementations

Four storage implementations are included for common use cases. All are used via `useStorage()`.

#### InMemoryStorage

An in-memory, array-backed storage implementation. Suitable for:

- **Swoole**: all connections share the same process memory, so reads and writes are visible to every client.
- **PCNTL** with pre-seeded, read-only data: data seeded before `run()` is inherited by all forked child processes.

> **⚠️ PCNTL write caveat**
>
> Under the PCNTL runner, `InMemoryStorage` is **not safe for multi-client write workloads**. Each forked child receives
> its own copy of the store at fork time. Written data is not propagated.
>
> Use one of `JsonFileStorage`, `SqliteStorage`, or `MysqlStorage` if you need write behavior and use PCNTL.

```php
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;

$passwordHash = '{SHA}' . base64_encode(sha1('secret', true));

$server = (new LdapServer())->useStorage(new InMemoryStorage([
    new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
    new Entry(
        new Dn('cn=admin,dc=example,dc=com'),
        new Attribute('cn', 'admin'),
        new Attribute('userPassword', $passwordHash),
    ),
]));
$server->run();
```

#### JsonFileStorage

A file-backed storage implementation that persists the directory as a JSON file. Safe for PCNTL (write operations are
serialised with `flock(LOCK_EX)` and the in-memory read cache is invalidated via `filemtime` checks).

Use the named constructor that matches your server runner:

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\JsonFileStorage;

// PCNTL runner — uses flock() to serialise writes across forked processes
$server = (new LdapServer())->useStorage(JsonFileStorage::forPcntl('/var/lib/myapp/ldap.json'));
$server->run();

// Swoole runner — uses a coroutine Channel mutex and non-blocking file I/O
$server = (new LdapServer())->useStorage(JsonFileStorage::forSwoole('/var/lib/myapp/ldap.json'));
$server->run();
```

JSON format:

```json
{
  "cn=admin,dc=example,dc=com": {
    "dn": "cn=admin,dc=example,dc=com",
    "attributes": {
      "cn": ["admin"],
      "userPassword": ["{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="]
    }
  }
}
```

#### SqliteStorage

A SQLite-backed storage implementation that persists the directory in a SQLite database file via PDO. Suitable for
use cases that need durable persistence across restarts with support for concurrent access:

- **PCNTL**: a single shared PDO connection is inherited by all forked child processes. SQLite WAL mode handles concurrent access at the OS level.
- **Swoole**: each coroutine gets its own PDO connection to avoid blocking.

Use the named constructor that matches your server runner:

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqliteStorage;

// PCNTL runner — WAL journal mode, shared connection
$server = (new LdapServer())->useStorage(SqliteStorage::forPcntl('/var/lib/myapp/ldap.sqlite'));
$server->run();

// Swoole runner — WAL journal mode, per-coroutine connection
$server = (new LdapServer())->useStorage(SqliteStorage::forSwoole('/var/lib/myapp/ldap.sqlite'));
$server->run();
```

Use `:memory:` as the path to run a non-persistent, in-process SQLite database (useful for testing):

```php
$server = (new LdapServer())->useStorage(SqliteStorage::forPcntl(':memory:'));
```

#### MysqlStorage

A MySQL/MariaDB-backed storage implementation. Requires MySQL 8.0+ or MariaDB 10.6+.

Use the named constructor that matches your server runner:

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\MysqlStorage;

// PCNTL runner — shared connection across forked processes
$server = (new LdapServer())->useStorage(
    MysqlStorage::forPcntl('mysql:host=localhost;dbname=ldap', 'user', 'secret')
);
$server->run();

// Swoole runner — per-coroutine connection
$server = (new LdapServer())->useStorage(
    MysqlStorage::forSwoole('mysql:host=localhost;dbname=ldap', 'user', 'secret')
);
$server->run();
```

The DSN follows the standard PDO MySQL format. The character set is automatically configured to `utf8mb4`
and the time zone to UTC on each connection.

##### Custom PDO driver

`SqliteStorage` and `MysqlStorage` are both factories for `PdoStorage`, which is the generic PDO-backed
implementation. To support a different database engine, implement `PdoStorageFactoryInterface` with
`PdoStorageFactoryTrait` and supply the appropriate `PdoDialectInterface`, filter translator, and
connection opener:

```php
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoStorageFactoryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoStorageFactoryTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use PDO;

final class PostgresStorage implements PdoStorageFactoryInterface
{
    use PdoStorageFactoryTrait;

    public function __construct(
        private readonly string $dsn,
        private readonly string $username,
        #[\SensitiveParameter]
        private readonly string $password,
    ) {
    }

    public static function forPcntl(
        string $dsn,
        string $username,
        #[\SensitiveParameter]
        string $password,
    ): PdoStorage {
        return (new self($dsn, $username, $password))->createShared();
    }

    public static function forSwoole(
        string $dsn,
        string $username,
        #[\SensitiveParameter]
        string $password,
    ): PdoStorage {
        return (new self($dsn, $username, $password))->createPerCoroutine();
    }

    protected function dialect(): PdoDialectInterface
    {
        return new MyPostgresDialect();
    }

    protected function translator(): FilterTranslatorInterface
    {
        return new MyPostgresFilterTranslator();
    }

    protected function openConnection(PdoDialectInterface $dialect): PDO
    {
        $pdo = new PDO(
            $this->dsn,
            $this->username,
            $this->password,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
        );

        PdoStorage::initialize($pdo, $dialect);

        return $pdo;
    }
}
```

### Custom Filter Evaluation

By default, a pure-PHP `FilterEvaluator` is applied to entries yielded by `search()` as a correctness
guarantee. For backends that translate LDAP filters to a native query language (SQL, MongoDB, etc.) and return
pre-filtered results, you can replace the evaluator:

```php
use FreeDSx\Ldap\LdapServer;
use App\MyBackend;
use App\MySqlFilterEvaluator;

$server = (new LdapServer())
    ->useBackend(new MyBackend())
    ->useFilterEvaluator(new MySqlFilterEvaluator());

$server->run();
```

The custom evaluator must implement `FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface`:

```php
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;

class MySqlFilterEvaluator implements FilterEvaluatorInterface
{
    public function evaluate(Entry $entry, FilterInterface $filter): bool
    {
        // Custom matching logic (e.g. bitwise matching rules for AD compatibility).
        return true;
    }
}
```

## LDIF Data

`seed()`, `applyChanges()`, and `dump()` all stream. LDIF input is always taken through `LdifLoaderInterface`
such as `FileLdifLoader` for a path, `StringLdifLoader` for an in-memory string, or your own implementation for any
other source (database, remote URL, gzip stream, etc.). LDIF output uses the parallel `LdifOutputInterface` such as 
`FileLdifOutput` and `StringLdifOutput`.

### Seeding Initial Entries

`LdapServer::seed()` bulk-imports RFC 2849 LDIF content records into the storage configured via `useStorage()` in one
atomic transaction, with schema validation and operational-attribute stamping (`createTimestamp`, `entryUUID`, etc.)
applied. Use it to populate a persistent storage backend before `$server->run()`.

```php
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Ldif\Loader\FileLdifLoader;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqliteStorage;

$server = (new LdapServer())
    ->useStorage(SqliteStorage::forPcntl('/var/lib/myapp/ldap.sqlite'))
    ->seed(
        new FileLdifLoader('/etc/myapp/initial-data.ldif'),
        new Dn('cn=admin,dc=example,dc=com'),
    );

$server->run();
```

The optional second argument is the creator DN, stamped as `creatorsName`/`modifiersName` on each imported entry —
defaults to the empty (anonymous) DN.

`seed()` accepts only content records (entries without `changetype:`) and requires depth-first input (parents first,
then children entries). LDIF produced by `dump()` is already in this order. The operation itself is an upsert that overwrites.

For Swoole factories (`::forSwoole()`), call `seed()` inside `Swoole\Coroutine\run()` so the adapter's
coroutine-scoped connection is available during import.

### Replaying LDIF Changelogs

`LdapServer::applyChanges()` replays an LDIF changelog through the live write path. Use it for applying diffs, migrations,
or administrative changes after the initial directory is populated.

```ldif
version: 1

dn: cn=alice,dc=example,dc=com
changetype: modify
replace: sn
sn: Anderson
-

dn: cn=bob,dc=example,dc=com
changetype: delete

dn: cn=carol,dc=example,dc=com
changetype: modrdn
newrdn: cn=carolyn
deleteoldrdn: 1
```

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Ldif\Loader\FileLdifLoader;

(new LdapServer())
    ->useStorage($storage)
    ->seed(new FileLdifLoader('/etc/myapp/initial-data.ldif'))
    ->applyChanges(new FileLdifLoader('/etc/myapp/changes-today.ldif'))
    ->run();
```

Unlike `seed()`, `applyChanges()` dispatches each request through the same write path the live server uses for client
requests. Supported changetypes: `add`, `delete`, `modify` (`add:`/`delete:`/`replace:` mod-specs), and `modrdn`/`moddn`
(rename or move; supports optional `newsuperior:` for moving across subtrees).

### Dumping the Directory

`LdapServer::dump()` streams the configured storage backend's entries to an LDIF output as RFC 2849 content records.
Operational attributes (`entryUUID`, `createTimestamp`, etc.) are preserved. So `dump()` then `seed()` restores the
entries exactly as they were.

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Ldif\Output\FileLdifOutput;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqliteStorage;

(new LdapServer())
    ->useStorage(SqliteStorage::forPcntl('/var/lib/myapp/ldap.sqlite'))
    ->dump(new FileLdifOutput('/var/backups/ldap-snapshot.ldif'));
```

For in-memory use (logging, tests, piping over the network) use `StringLdifOutput`, which collects the chunks and is
both `Stringable` and exposes `getLdif()`:

```php
use FreeDSx\Ldap\Ldif\Output\StringLdifOutput;

$output = new StringLdifOutput();
$server->dump($output);

echo $output; // or $output->getLdif()
```

Use `DumpOptions` to filter the dump by any filter you want. Useful for partial backups or extracting a single OU:

```php
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Export\DumpOptions;

$options = (new DumpOptions())
    ->setBaseDn(new Dn('ou=people,dc=example,dc=com'))
    ->setFilter(Filters::equal('objectClass', 'inetOrgPerson'));

$server->dump(
    new FileLdifOutput('/tmp/people.ldif'),
    $options,
);
```

### Inspecting Parsed LDIF

For one-off tooling that needs to inspect a parsed LDIF before applying it (counting records, filtering by changetype,
etc) `LdifChanges` is a buffered collection with type filters:

```php
use FreeDSx\Ldap\Ldif\LdifChanges;
use FreeDSx\Ldap\Ldif\Loader\FileLdifLoader;

$changes = LdifChanges::fromLoader(new FileLdifLoader('/path/to/changes.ldif'));

foreach ($changes->entries() as $entry) {
    // each AddRequest's Entry
}

$changes->count();     // total changes
$changes->adds();      // AddRequest[]
$changes->modifies();  // ModifyRequest[]
$changes->deletes();   // DeleteRequest[]
$changes->modifyDns(); // ModifyDnRequest[]
```

`LdifChanges::fromString($ldif)` is the same flow for an in-memory string. The collection materializes every request,
so prefer the streaming `seed()`/`applyChanges()`/`dump()` methods normal data paths; `LdifChanges` is best suited to
small change sets.

## Authentication

The `PasswordAuthenticatableInterface` covers all bind types through two methods:

```php
interface PasswordAuthenticatableInterface
{
    // Called for simple binds.
    public function authenticate(
        string $name,
        string $password,
    ): AuthenticatedTokenInterface;

    // Called for all SASL mechanisms (PLAIN, CRAM-MD5, DIGEST-MD5, SCRAM-*).
    // Return a SaslIdentity with the stored password and resolved DN, or null to reject.
    public function getSaslIdentity(
        string $username,
        MechanismName $mechanism,
    ): ?SaslIdentity;
}
```

### Default Authentication

When no explicit authenticator is registered, we build a `PasswordAuthenticator` automatically. It
resolves the bind name to an entry via the backend's `get()` method (or a custom resolver — see below), then verifies
the supplied password against the `userPassword` attribute. Supported schemes: `{SHA}`, `{SSHA}`, `{MD5}`, `{SMD5}`,
and plaintext.

This means simple bind authentication works out of the box with any backend that stores `userPassword` on entries —
no additional configuration required.

### Custom Bind Name Resolution

By default, the built-in `PasswordAuthenticator` treats the bind name as a literal DN. If clients bind with a
non-DN identifier (a bare username, an email address, etc.), configure `AttributeSearchBindNameResolver` or
supply a custom `BindNameResolverInterface` via `setIdentityResolver()`:

```php
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\AttributeSearchBindNameResolver;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;

$server = new LdapServer(
    (new ServerOptions)->setIdentityResolver(
        new AttributeSearchBindNameResolver(
            baseDn: 'ou=People,dc=example,dc=com',
            attribute: 'mail',
        ),
    )
);
```

The resolver applies to simple bind, SASL bind, and Password Modify identity resolution. See
[Configuration](Configuration.md#setidentityresolver) for full details.

### Custom Authenticator

For full control — external auth services, custom credential storage, etc. — implement
`PasswordAuthenticatableInterface` and register it:

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\SaslIdentity;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Sasl\Mechanism\MechanismName;
use SensitiveParameter;

class MyAuthenticator implements PasswordAuthenticatableInterface
{
    public function authenticate(
        string $name,
        #[SensitiveParameter]
        string $password,
    ): AuthenticatedTokenInterface {
        // Your simple-bind credential verification logic.
    }

    public function getSaslIdentity(
        string $username,
        MechanismName $mechanism,
    ): ?SaslIdentity {
        // Return a SaslIdentity with the stored password and resolved DN, or null to reject.
        // Challenge mechanisms require a plaintext or recoverable password.
    }
}

$server = (new LdapServer())->usePasswordAuthenticator(new MyAuthenticator());
```

## Handling the RootDSE

The server generates a default RootDSE. `namingContexts` is derived from the backend (storage contents, or whatever a
custom backend declares); other attributes such as `vendorName` come from `ServerOptions`. For most deployments this is
sufficient. The default entry always advertises:

- `supportedControl`: paging (RFC 2696)
- `supportedExtension`: WhoAmI (RFC 4532), Password Modify (RFC 3062), and StartTLS (RFC 4511) if an SSL certificate is configured
- `supportedLDAPVersion`: `3`

If you need full control (for example to add custom attributes) implement `RootDseHandlerInterface`. Your
implementation receives the default-generated entry and returns a (possibly modified) entry to send back to the
client. (A `makeProxy()` server forwards RootDSE requests to the upstream automatically, so this is not needed there.)

For a custom handler:

```php
namespace App;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;

class MyRootDseHandler implements RootDseHandlerInterface
{
    public function rootDse(
        RequestContext $context,
        SearchRequest $request,
        Entry $rootDse,
    ): Entry {
        // Modify the default entry or return a completely custom one.
        $rootDse->set('namingContexts', 'dc=example,dc=com');

        return $rootDse;
    }
}
```

Register it with the server:

```php
use FreeDSx\Ldap\LdapServer;
use App\MyRootDseHandler;

$server = (new LdapServer())
    ->useBackend(new MyBackend())
    ->useRootDseHandler(new MyRootDseHandler());

$server->run();
```

If your backend class also implements `RootDseHandlerInterface`, you do not need to call `useRootDseHandler()` — it will be used automatically.

## SASL Authentication

The server supports SASL bind requests. SASL must be explicitly enabled by configuring the mechanisms you want to
support via `ServerOptions::setSaslMechanisms()`. The configured mechanisms are advertised to clients through the
`supportedSaslMechanisms` RootDSE attribute.

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;

$server = new LdapServer(
    (new ServerOptions)->setSaslMechanisms(
        ServerOptions::SASL_PLAIN,
        ServerOptions::SASL_SCRAM_SHA_256,
    )
);
```

All SASL mechanisms are handled through `PasswordAuthenticatableInterface`. No separate interface or backend
modification is needed.

### PLAIN Mechanism

The `PLAIN` mechanism extracts the username and password from the SASL credentials and calls
`PasswordAuthenticatableInterface::getSaslIdentity()`. The built-in `PasswordAuthenticator` then verifies the
supplied password against the stored `userPassword` using `PasswordHashVerifier`, which supports `{SHA}`, `{SSHA}`,
`{MD5}`, `{SMD5}`, and plaintext. No additional configuration is needed beyond enabling the mechanism.

**Note**: PLAIN transmits credentials in cleartext. Only enable it when the connection is protected by TLS (StartTLS
or `setUseSsl`).

### Challenge-Based Mechanisms (CRAM-MD5, DIGEST-MD5, and SCRAM)

`CRAM-MD5`, `DIGEST-MD5`, and the `SCRAM-*` family are challenge-response mechanisms. The server issues a challenge
to the client and verifies the response against a digest computed from the user's plaintext password. The server calls
`PasswordAuthenticatableInterface::getSaslIdentity()` to retrieve the password.

The built-in `PasswordAuthenticator` reads the raw `userPassword` attribute from the resolved entry. This works when
passwords are stored in plaintext. If passwords are stored as one-way hashes (bcrypt, argon2) you must supply a
custom authenticator that can return a recoverable value.

**Note**: Because challenge mechanisms require a recoverable password, they are fundamentally incompatible with
one-way hashing. If one-way hashing is a hard requirement, use `PLAIN` over TLS instead.

### Identity Resolution for SASL

The built-in `PasswordAuthenticator` resolves SASL identities using a resolver chain. A full DN is tried first;
if that lookup returns no entry, the configured resolver (or `AttributeSearchBindNameResolver` searching by `uid`
by default) is applied. This same chain also drives simple bind and Password Modify identity resolution.

Configure the resolver via `setIdentityResolver()` when your directory uses a different attribute or a restricted
search base:

```php
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\AttributeSearchBindNameResolver;
use FreeDSx\Ldap\ServerOptions;

$options = (new ServerOptions)
    ->setIdentityResolver(
        new AttributeSearchBindNameResolver(
            baseDn: 'ou=People,dc=example,dc=com',
            attribute: 'mail',
        ),
    );
```

**SCRAM variants**: The following constants are available. `SCRAM-SHA-256` is the recommended choice for new
deployments ([RFC 7677](https://www.rfc-editor.org/rfc/rfc7677) standardises it as the preferred mechanism).

| Constant                             | Mechanism                       |
|--------------------------------------|---------------------------------|
| `ServerOptions::SASL_SCRAM_SHA_1`    | `SCRAM-SHA-1`                   |
| `ServerOptions::SASL_SCRAM_SHA_256`  | `SCRAM-SHA-256` *(recommended)* |
| `ServerOptions::SASL_SCRAM_SHA_384`  | `SCRAM-SHA-384`                 |
| `ServerOptions::SASL_SCRAM_SHA_512`  | `SCRAM-SHA-512`                 |
| `ServerOptions::SASL_SCRAM_SHA3_512` | `SCRAM-SHA3-512`                |

Channel-binding (`-PLUS`) variants of each are also available (e.g. `SASL_SCRAM_SHA_256_PLUS`) for environments where
TLS channel binding is required.

## StartTLS SSL Certificate Support

To allow clients to issue a StartTLS command against the LDAP server you need to provide an SSL certificate, key, and
key passphrase/password (if needed) when constructing the server class. If these are not present then the StartTLS
request will not be supported.

Adding the generated certs and keys on construction:

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;

$options = (new ServerOptions)
    # The key can also be bundled in this cert
    ->setSslCert('/path/to/cert.pem')
    # The key for the cert. Not needed if bundled above.
    ->setSslCertKey('/path/to/cert.key')
    # The password/passphrase to read the key (if required)
    ->setSslCertPassphrase('This-Is-My-Secret-Password');

$server = new LdapServer($options);

$server->run();
```

## Password Modify Extended Operation

The server supports RFC 3062 Password Modify (OID `1.3.6.1.4.1.4203.1.11.1`). Authenticated clients may change
their own password or — if permitted by the configured access control — another user's password.

### Self-service password change

A client changes its own password by omitting `userIdentity`. The server resolves the target entry from the bound
DN. Supply the current password in `oldPassword` for verification:

```php
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;

$client->sendAndReceive(
    new PasswordModifyRequest(null, 'currentPassword', 'newPassword'),
);
```

### Server-generated passwords

Omit `newPassword` to let the server generate a secure random password. The generated password is returned in the
response:

```php
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;

/** @var PasswordModifyResponse $response */
$response = $client->sendAndReceive(
    new PasswordModifyRequest(null, 'currentPassword', null),
)->getResponse();

$generated = $response->getGeneratedPassword(); // 16-character random string
```

### Admin password reset

An admin may reset another user's password by supplying a `userIdentity`. The identity is resolved using the same
chain as bind operations — a full DN, or any name your configured `setIdentityResolver()` understands:

```php
$client->sendAndReceive(
    new PasswordModifyRequest('cn=user,dc=example,dc=com', null, 'resetPassword'),
);
```

### Access control

Password Modify is protected at two levels:

1. **Operation level** (`OperationType::PasswordModify`) — controls who may invoke the operation.
2. **Attribute level** (`userPassword`) — controls who may write the password attribute.

See [Access Control](Access-Control.md) for rule configuration. Anonymous access is always denied before the
handler runs when `requireAuthentication` is enabled (the default).
