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

namespace FreeDSx\Ldap\Protocol\Authorization;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\ProxyAuthorizationControl;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\UnexpectedValueException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;

use function count;
use function in_array;
use function str_starts_with;
use function substr;

/**
 * Resolves the effective identity for an operation carrying an RFC 4370 proxied authorization control.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ProxiedAuthorizationResolver
{
    /**
     * Extended operations the control must not be honored for: those changing authentication, authorization, or
     * confidentiality (RFC 4370 §4).
     */
    private const INELIGIBLE_EXTENDED_OIDS = [
        ExtendedRequest::OID_START_TLS,
        ExtendedRequest::OID_PWD_MODIFY,
    ];

    public function __construct(
        private AccessControlInterface $accessControl,
        private LdapBackendInterface $backend,
        private BindNameResolverInterface $identityResolver,
        private EventLogger $eventLogger,
    ) {}

    /**
     * Returns the token the operation should run under: the bound token when no proxy control is present, otherwise the
     * proxied identity (after authorizing the bound identity to assume it).
     *
     * @throws OperationException
     */
    public function resolve(
        RequestInterface $request,
        ControlBag $controls,
        TokenInterface $token,
    ): TokenInterface {
        $proxyControls = $this->proxyControlsFrom($controls);

        if ($proxyControls === []) {
            return $token;
        }

        if (count($proxyControls) > 1) {
            throw new OperationException(
                'Only one proxied authorization control may be present in a request.',
                ResultCode::PROTOCOL_ERROR,
            );
        }
        $control = $proxyControls[0];

        # RFC 4370 §3: the control MUST be critical; reject a non-critical one rather than coercing it.
        if (!$control->getCriticality()) {
            throw new OperationException(
                'The proxied authorization control must be marked critical.',
                ResultCode::PROTOCOL_ERROR,
            );
        }

        # RFC 4370 §4: not valid on bind/unbind/abandon or on extensions that change authn/authz/confidentiality.
        if (!$this->isProxyEligible($request)) {
            throw new OperationException(
                'The proxied authorization control is not supported for this operation.',
                ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
            );
        }

        $authzId = $control->getAuthzId();

        if (!$token instanceof AuthenticatedTokenInterface) {
            $this->denyProxy(
                $token,
                $authzId,
            );
        }

        # Coarse capability gate before any directory lookup, so a caller with no proxy grant cannot drive resolution.
        if (!$this->accessControl->mayUseControl($token, Control::OID_PROXY_AUTHORIZATION)) {
            $this->denyProxy(
                $token,
                $authzId,
            );
        }

        return $this->effectiveToken(
            $authzId,
            $token,
        );
    }

    /**
     * @return ProxyAuthorizationControl[]
     */
    private function proxyControlsFrom(ControlBag $controls): array
    {
        $found = [];

        foreach ($controls as $control) {
            if ($control instanceof ProxyAuthorizationControl) {
                $found[] = $control;
            }
        }

        return $found;
    }

    private function isProxyEligible(RequestInterface $request): bool
    {
        if ($request instanceof ExtendedRequest) {
            return !in_array(
                $request->getName(),
                self::INELIGIBLE_EXTENDED_OIDS,
                true,
            );
        }

        return !($request instanceof UnbindRequest || $request instanceof AbandonRequest);
    }

    /**
     * @throws OperationException
     */
    private function effectiveToken(
        string $authzId,
        AuthenticatedTokenInterface $token,
    ): TokenInterface {
        if ($authzId === '') {
            $this->authorizeProxy(
                $token,
                new Dn(''),
                $authzId,
            );

            return new AnonToken(
                null,
                $token->getVersion(),
                $token->getResolvedDn(),
            );
        }

        $proxiedDn = $this->resolveAuthzId(
            $authzId,
            $token,
        )->getDn();
        $this->authorizeProxy(
            $token,
            $proxiedDn,
            $authzId,
        );

        return BindToken::fromSasl(
            username: $proxiedDn->toString(),
            resolvedDn: $proxiedDn,
            version: $token->getVersion(),
            authorizingDn: $token->getResolvedDn(),
        );
    }

    /**
     * Resolves an authzId ("dn:..." / "u:...") to its directory entry; denies on an unknown form, malformed DN, or
     * no match.
     *
     * @throws OperationException
     */
    private function resolveAuthzId(
        string $authzId,
        AuthenticatedTokenInterface $token,
    ): Entry {
        try {
            $entry = match (true) {
                str_starts_with($authzId, 'dn:') => $this->backend->get(new Dn(substr($authzId, 3))),
                str_starts_with($authzId, 'u:') => $this->identityResolver->resolve(substr($authzId, 2), $this->backend),
                default => null,
            };
        } catch (OperationException|UnexpectedValueException|InvalidArgumentException) {
            $this->denyProxy(
                $token,
                $authzId,
            );
        }

        if ($entry === null) {
            $this->denyProxy(
                $token,
                $authzId,
            );
        }

        return $entry;
    }

    /**
     * @throws OperationException
     */
    private function authorizeProxy(
        AuthenticatedTokenInterface $token,
        Dn $proxiedDn,
        string $authzId,
    ): void {
        try {
            $this->accessControl->authorizeControl(
                $token,
                $proxiedDn,
                Control::OID_PROXY_AUTHORIZATION,
            );
        } catch (OperationException) {
            $this->denyProxy(
                $token,
                $authzId,
            );
        }
    }

    /**
     * Records the denial (including the attempted authzId for audit) and throws a generic denial to the client.
     *
     * @throws OperationException
     */
    private function denyProxy(
        TokenInterface $token,
        string $authzId,
    ): never {
        $exception = new OperationException(
            'Proxied authorization denied.',
            ResultCode::AUTHORIZATION_DENIED,
        );
        $this->eventLogger->recordFailure(
            ServerEvent::ProxyAuthorizationDenied,
            $exception,
            [
                EventContext::CONTROL_OIDS => [Control::OID_PROXY_AUTHORIZATION],
                EventContext::AUTHZ_ID => $authzId,
            ],
            subject: $token,
        );

        throw $exception;
    }
}
