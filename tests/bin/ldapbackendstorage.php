<?php

declare(strict_types=1);

/**
 * Server bootstrap script for LdapBackendStorageTest.
 *
 * Seeds an InMemoryStorageAdapter with a small directory and starts the server
 * using LdapServer::useStorageAdapter(). This exercises the full stack:
 * BackendStorageRequestHandler + FilterEvaluator + InMemoryStorageAdapter.
 *
 * Entries seeded:
 *   dc=foo,dc=bar                       (base)
 *   cn=user,dc=foo,dc=bar               (password: 12345)
 *   ou=people,dc=foo,dc=bar
 *   cn=alice,ou=people,dc=foo,dc=bar    (sn=Smith, mail=alice@foo.bar)
 */

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Storage\Adapter\InMemoryStorageAdapter;
use FreeDSx\Ldap\ServerOptions;

require __DIR__ . '/../../vendor/autoload.php';

$passwordHash = '{SHA}' . base64_encode(sha1('12345', true));

$adapter = new InMemoryStorageAdapter(
    new Entry(
        new Dn('dc=foo,dc=bar'),
        new Attribute('dc', 'foo'),
        new Attribute('objectClass', 'domain'),
    ),
    new Entry(
        new Dn('cn=user,dc=foo,dc=bar'),
        new Attribute('cn', 'user'),
        new Attribute('objectClass', 'inetOrgPerson'),
        new Attribute('userPassword', $passwordHash),
    ),
    new Entry(
        new Dn('ou=people,dc=foo,dc=bar'),
        new Attribute('ou', 'people'),
        new Attribute('objectClass', 'organizationalUnit'),
    ),
    new Entry(
        new Dn('cn=alice,ou=people,dc=foo,dc=bar'),
        new Attribute('cn', 'alice'),
        new Attribute('objectClass', 'inetOrgPerson'),
        new Attribute('sn', 'Smith'),
        new Attribute('mail', 'alice@foo.bar'),
    ),
);

$server = (new LdapServer(
    (new ServerOptions())
        ->setPort(3389)
        ->setTransport('tcp')
))->useStorageAdapter($adapter);

echo 'server starting...' . PHP_EOL;

$server->run();
