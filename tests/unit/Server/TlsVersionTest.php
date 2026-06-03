<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Unit\FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Server\TlsVersion;
use PHPUnit\Framework\TestCase;

final class TlsVersionTest extends TestCase
{
    public function test_tls_1_3_enables_only_tls_1_3(): void
    {
        self::assertSame(
            STREAM_CRYPTO_METHOD_TLSv1_3_SERVER,
            TlsVersion::Tls1_3->toServerCryptoMethod(),
        );
    }

    public function test_tls_1_2_enables_1_2_and_1_3(): void
    {
        self::assertSame(
            STREAM_CRYPTO_METHOD_TLSv1_2_SERVER
            | STREAM_CRYPTO_METHOD_TLSv1_3_SERVER,
            TlsVersion::Tls1_2->toServerCryptoMethod(),
        );
    }

    public function test_tls_1_1_enables_1_1_through_1_3(): void
    {
        self::assertSame(
            STREAM_CRYPTO_METHOD_TLSv1_1_SERVER
            | STREAM_CRYPTO_METHOD_TLSv1_2_SERVER
            | STREAM_CRYPTO_METHOD_TLSv1_3_SERVER,
            TlsVersion::Tls1_1->toServerCryptoMethod(),
        );
    }

    public function test_tls_1_0_enables_all_tls_versions(): void
    {
        self::assertSame(
            STREAM_CRYPTO_METHOD_TLSv1_0_SERVER
            | STREAM_CRYPTO_METHOD_TLSv1_1_SERVER
            | STREAM_CRYPTO_METHOD_TLSv1_2_SERVER
            | STREAM_CRYPTO_METHOD_TLSv1_3_SERVER,
            TlsVersion::Tls1_0->toServerCryptoMethod(),
        );
    }
}
