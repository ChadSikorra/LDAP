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

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\ProxyAuthorizationControl;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

use function count;
use function in_array;

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
        private AuthzIdResolver $authzIdResolver,
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

        if (!$token instanceof AuthenticatedTokenInterface) {
            $this->authzIdResolver->deny(
                $token,
                $control->getRawAuthzId(),
            );
        }

        try {
            $authzId = $control->getAuthzId();
        } catch (InvalidArgumentException) {
            $this->authzIdResolver->deny(
                $token,
                $control->getRawAuthzId(),
            );
        }

        return $this->authzIdResolver->assume(
            $token,
            $authzId,
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
}
