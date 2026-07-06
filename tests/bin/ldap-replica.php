<?php

declare(strict_types=1);

use Symfony\Component\Console\Application;
use Tests\Support\FreeDSx\Ldap\LdapReplicaCommand;

require __DIR__ . '/../../vendor/autoload.php';

$command = new LdapReplicaCommand();
$app = new Application('LDAP test replica');
$app->add($command);
$app->setDefaultCommand(
    (string) $command->getName(),
    true,
);
$app->run();
