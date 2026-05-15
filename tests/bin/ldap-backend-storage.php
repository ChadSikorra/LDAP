<?php

declare(strict_types=1);

use Symfony\Component\Console\Application;
use Tests\Support\FreeDSx\Ldap\LdapBackendStorageCommand;

require __DIR__ . '/../../vendor/autoload.php';

$command = new LdapBackendStorageCommand();
$app = new Application('LDAP backend storage test server');
$app->add($command);
$app->setDefaultCommand(
    (string) $command->getName(),
    true,
);
$app->run();
