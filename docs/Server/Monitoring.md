# Server Monitoring

The server can report aggregate metrics two ways:

* **`cn=monitor`**: an in-band entry any LDAP client can read with a base-scope search. Good for a quick health check.
* **A metrics recorder**: an out-of-band sink (Prometheus, StatsD, logs) that receives every operation and connection
  event. Good for dashboards, and it keeps reporting when the server is too busy to answer a `cn=monitor` query.

Both are off by default.

* [Quick Start](#quick-start)
* [The cn=monitor Entry](#the-cnmonitor-entry)
* [Access Control](#access-control)
* [Runner Differences](#runner-differences)
* [Push Exporters](#push-exporters)

## Quick Start

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\ServerOptions;

$server = new LdapServer(
    (new ServerOptions())
        ->setMonitorEnabled(true),
);
```

Then read it (authenticated; see [Access Control](#access-control)):

```php
$client->bind('cn=user,dc=example,dc=com', 'secret');

$entry = $client->read('cn=monitor');
```

The monitor DN is the fixed, well-known `cn=monitor`. When the feature is off the route is not registered, so a real
`cn=monitor` entry in your backend is never shadowed.

## The cn=monitor Entry

`objectClass: top, extensibleObject`. The attributes are operational, and any value that cannot be determined is left
off rather than returned empty.

| Attribute | Meaning |
| --- | --- |
| `serverHost` | Host name, to tell instances apart behind a load balancer. |
| `serverVersion` | The configured DSE vendor version, if set. |
| `serverRunner` | The runner class in use. |
| `serverStartTime`, `serverUptimeSeconds` | Start time and seconds since. |
| `configReloadCount`, `configReloadTime` | SIGHUP reload count and last reload time. |
| `connectionsActive` | Currently-open connections. |
| `connectionsTotal` | Connections accepted since start. |
| `connectionsRejected` | Connections turned away at the connection limit. |
| `connectionsWriteTimeouts`, `connectionsIdleTimeouts` | Connections closed by the write or idle timeout. |
| `connectionsMax` | The configured connection limit (`0` is unlimited). |
| `operationsCompleted`, `operationsFailed` | Total operations and the failed subset. |
| `operationsByType` | Per-type counts, e.g. `search=1402, bind=210, add=8`. |

Counters are monotonic since start and are never reset, so sample and diff them to get rates. A restart starts them over.

## Access Control

`cn=monitor` is authorized like any other base-scope search. With the default deny-anonymous access control it is
authenticated-only. To restrict it further, add `RuleBasedAccessControl` rules targeting the monitor DN. See
[Access Control](Access-Control.md).

## Runner Differences

* **Swoole** runs in one process, so `cn=monitor` is fully live.
* **PCNTL** forks per connection. Connection gauges are authoritative, and operation counts stay current to within about
  one accept cycle (`setSocketAcceptTimeout`), including on long-lived connections. They are best-effort: a forcibly
  killed worker may lose its most recent operations.

Under PCNTL the monitor data is published to a JSON file, by default under the system temp directory keyed by port. Set
`setMonitorSnapshotPath()` to relocate it or to avoid collisions when running several instances on one host.

For per-operation aggregation that survives saturation or spans instances, prefer a push exporter.

## Push Exporters

Provide any `MetricsRecorderInterface` to receive events out-of-band:

```php
$options->setMetricsRecorder($myRecorder);
```

It is notified of each operation (`operationObserved`), connection lifecycle event (`connectionObserved`), server start,
and config reload. The recorder and `cn=monitor` are independent, so the two options compose:

| `setMonitorEnabled` | `setMetricsRecorder` | Result |
| --- | --- | --- |
| off | none | No-op, no overhead. |
| off | your recorder | Push only. No `cn=monitor` entry; your sink receives every event. |
| on | none | `cn=monitor` only. |
| on | your recorder | Both the in-band entry and out-of-band push. |

Prometheus is pull-based, but under PCNTL each process records its own events and a forked worker cannot host a scrape
endpoint, so push each process's events to a Pushgateway or StatsD. Under the single-process Swoole runner a pull-based
`/metrics` endpoint works. No Prometheus or StatsD adapters are bundled; implement the interface against your client.

When running the PCNTL runner, prefer `opcache.jit=off`; see the JIT note in [General Usage](General-Usage.md).
