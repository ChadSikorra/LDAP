<?php

declare(strict_types=1);

/**
 * Server bootstrap script for AclIntegrationTest.
 *
 * Usage: php ldap-acl.php [transport]
 */

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\AccessControl\OperationType;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Target\Target;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\ServerOptions;

require __DIR__ . '/../../vendor/autoload.php';

$transport = $argv[1] ?? 'tcp';

$adminPasswordHash = '{SHA}' . base64_encode(sha1('adminpass', true));
$userPasswordHash = '{SHA}' . base64_encode(sha1('12345', true));
$alicePasswordHash = '{SHA}' . base64_encode(sha1('alicepass', true));

$entries = [
    new Entry(
        new Dn('dc=foo,dc=bar'),
        new Attribute('dc', 'foo'),
        new Attribute('objectClass', 'domain'),
    ),
    new Entry(
        new Dn('cn=admins,dc=foo,dc=bar'),
        new Attribute('cn', 'admins'),
        new Attribute('objectClass', 'groupOfNames'),
        new Attribute('member', 'cn=admin,dc=foo,dc=bar'),
    ),
    new Entry(
        new Dn('cn=admin,dc=foo,dc=bar'),
        new Attribute('cn', 'admin'),
        new Attribute('sn', 'Admin'),
        new Attribute('objectClass', 'inetOrgPerson'),
        new Attribute('userPassword', $adminPasswordHash),
    ),
    new Entry(
        new Dn('cn=user,dc=foo,dc=bar'),
        new Attribute('cn', 'user'),
        new Attribute('sn', 'User'),
        new Attribute('objectClass', 'inetOrgPerson'),
        new Attribute('userPassword', $userPasswordHash),
    ),
    new Entry(
        new Dn('ou=people,dc=foo,dc=bar'),
        new Attribute('ou', 'people'),
        new Attribute('objectClass', 'organizationalUnit'),
    ),
    new Entry(
        new Dn('cn=alice,ou=people,dc=foo,dc=bar'),
        new Attribute('cn', 'alice'),
        new Attribute('sn', 'Smith'),
        new Attribute('objectClass', 'inetOrgPerson'),
        new Attribute('userPassword', $alicePasswordHash),
    ),
];

$server = new LdapServer(
    (new ServerOptions())
        ->setPort(10389)
        ->setTransport($transport)
        ->setSocketAcceptTimeout(0.1)
        ->setOnServerReady(fn() => fwrite(STDOUT, 'server starting...' . PHP_EOL))
        ->setOperationRules([
            OperationRule::allow(
                Subject::group('cn=admins,dc=foo,dc=bar'),
            ),
            OperationRule::allow(
                Subject::authenticated(),
                Target::any(),
                OperationType::Search,
                OperationType::Compare,
            ),
            OperationRule::allow(
                Subject::authenticated(),
                Target::subtree('ou=people,dc=foo,dc=bar'),
                OperationType::ModifyDn,
            ),
            OperationRule::allow(
                Subject::self(),
                Target::any(),
                OperationType::Modify,
            ),
            OperationRule::deny(Subject::anyone()),
        ])
        ->setAttributeRules([
            AttributeRule::allow(
                Subject::self(),
                Target::any(),
                'userPassword',
            ),
            AttributeRule::allow(
                Subject::group('cn=admins,dc=foo,dc=bar'),
                Target::any(),
                'userPassword',
            ),
            AttributeRule::deny(
                Subject::anyone(),
                Target::any(),
                'userPassword',
            ),
        ]),
);

$server->useStorage(new InMemoryStorage($entries));
$server->run();
