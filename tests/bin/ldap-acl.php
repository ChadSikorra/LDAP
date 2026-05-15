<?php

declare(strict_types=1);

use Symfony\Component\Console\Application;
use Tests\Support\FreeDSx\Ldap\LdapAclCommand;

require __DIR__ . '/../../vendor/autoload.php';

$command = new LdapAclCommand();
$app = new Application('LDAP ACL test server');
$app->add($command);
$app->setDefaultCommand(
    (string) $command->getName(),
    true,
);
$app->run();
