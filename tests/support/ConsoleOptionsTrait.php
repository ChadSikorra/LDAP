<?php

declare(strict_types=1);

namespace Tests\Support\FreeDSx\Ldap;

use Symfony\Component\Console\Input\InputInterface;

trait ConsoleOptionsTrait
{
    private function getStringOption(InputInterface $input, string $name): string
    {
        $value = $input->getOption($name);

        return is_string($value) ? $value : '';
    }
}
