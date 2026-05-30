<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\ProxyOptions;
use PHPUnit\Framework\TestCase;

final class ProxyOptionsTest extends TestCase
{
    public function test_it_exposes_the_client_options(): void
    {
        $clientOptions = new ClientOptions(['127.0.0.1']);

        self::assertSame(
            $clientOptions,
            (new ProxyOptions($clientOptions))->getClientOptions(),
        );
    }

    public function test_it_does_not_use_start_tls_by_default(): void
    {
        self::assertFalse((new ProxyOptions())->getUseStartTls());
    }

    public function test_it_can_enable_upstream_start_tls(): void
    {
        self::assertTrue(
            (new ProxyOptions())->setUseStartTls(true)->getUseStartTls(),
        );
    }
}
