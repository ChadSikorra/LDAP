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

namespace FreeDSx\Ldap\Server;

/**
 * Minimum TLS protocol version the server will negotiate.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum TlsVersion: string
{
    case Tls1_0 = '1.0';

    case Tls1_1 = '1.1';

    case Tls1_2 = '1.2';

    case Tls1_3 = '1.3';

    /**
     * The server-side `STREAM_CRYPTO_METHOD_*` bitmask enabling this version and every higher one.
     */
    public function toServerCryptoMethod(): int
    {
        return match ($this) {
            self::Tls1_0 => STREAM_CRYPTO_METHOD_TLSv1_0_SERVER
                | STREAM_CRYPTO_METHOD_TLSv1_1_SERVER
                | STREAM_CRYPTO_METHOD_TLSv1_2_SERVER
                | STREAM_CRYPTO_METHOD_TLSv1_3_SERVER,
            self::Tls1_1 => STREAM_CRYPTO_METHOD_TLSv1_1_SERVER
                | STREAM_CRYPTO_METHOD_TLSv1_2_SERVER
                | STREAM_CRYPTO_METHOD_TLSv1_3_SERVER,
            self::Tls1_2 => STREAM_CRYPTO_METHOD_TLSv1_2_SERVER
                | STREAM_CRYPTO_METHOD_TLSv1_3_SERVER,
            self::Tls1_3 => STREAM_CRYPTO_METHOD_TLSv1_3_SERVER,
        };
    }
}
