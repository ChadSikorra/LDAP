<?php

declare(strict_types=1);

use Symfony\Component\Console\Application;
use Tests\Support\FreeDSx\Ldap\LdapPasswordPolicyCommand;

require __DIR__ . '/../../vendor/autoload.php';

$command = new LdapPasswordPolicyCommand();
$app = new Application('LDAP password policy test server');
$app->add($command);
$app->setDefaultCommand(
    (string) $command->getName(),
    true,
);
$app->run();
