<?php

declare(strict_types=1);

use Symfony\Component\Console\Application;
use Tests\Support\FreeDSx\Ldap\LdapServerCommand;

require __DIR__ . '/../../vendor/autoload.php';

$command = new LdapServerCommand();
$app = new Application('LDAP test server');
$app->add($command);
$app->setDefaultCommand(
    (string) $command->getName(),
    true,
);
$app->run();
