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

namespace FreeDSx\Ldap\Server\Middleware\Pipeline;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Server\Logging\ConnectionContext;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Request-scoped state passed through the server middleware pipeline.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ServerRequestContext
{
    public function __construct(
        public LdapMessageRequest $message,
        private ?TokenInterface $token = null,
        public ConnectionContext $connectionContext = new ConnectionContext(),
    ) {}

    /**
     * The resolved identity, or null before authorization runs. Callers opting into this accept its absence.
     */
    public function token(): ?TokenInterface
    {
        return $this->token;
    }

    /**
     * The resolved identity for stages that run after authorization.
     *
     * @throws RuntimeException when no token has been resolved yet.
     */
    public function tokenOrFail(): TokenInterface
    {
        return $this->token ?? throw new RuntimeException('No token has been resolved for this request.');
    }

    public function withToken(TokenInterface $token): self
    {
        return new self(
            $this->message,
            $token,
            $this->connectionContext,
        );
    }
}
