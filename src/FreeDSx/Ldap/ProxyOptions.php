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

namespace FreeDSx\Ldap;

/**
 * Options for a forwarding proxy server.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ProxyOptions
{
    public function __construct(
        private ClientOptions $clientOptions = new ClientOptions(),
        private bool $useStartTls = false,
    ) {}

    /**
     * The client options used for the upstream connection (servers, TLS, timeouts).
     */
    public function getClientOptions(): ClientOptions
    {
        return $this->clientOptions;
    }

    public function setClientOptions(ClientOptions $clientOptions): self
    {
        $this->clientOptions = $clientOptions;

        return $this;
    }

    /**
     * Whether to issue StartTLS on the upstream connection before binding (use for upstream StartTLS; LDAPS uses ClientOptions::setUseSsl).
     */
    public function getUseStartTls(): bool
    {
        return $this->useStartTls;
    }

    public function setUseStartTls(bool $useStartTls): self
    {
        $this->useStartTls = $useStartTls;

        return $this;
    }
}
