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

namespace FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\AddResponse;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\CompareResponse;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\ModifyDnResponse;
use FreeDSx\Ldap\Operation\Response\ModifyResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;

/**
 * For a specific request and result code/diagnostic, get the response object if possible.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ResponseFactory
{
    /**
     * Retrieve the expected response type for the request that was given.
     *
     * @param Dn|null $matchedDn Matched ancestor; emitted as matchedDN when non-null.
     */
    public function getStandardResponse(
        LdapMessageRequest $message,
        int $resultCode = ResultCode::SUCCESS,
        string $diagnostic = '',
        ?Dn $matchedDn = null,
    ): LdapMessageResponse {
        $request = $message->getRequest();
        $dn = $matchedDn?->toString() ?? '';

        $response = match (true) {
            $request instanceof BindRequest => new BindResponse(
                new LdapResult(
                    $resultCode,
                    $dn,
                    $diagnostic,
                ),
            ),
            $request instanceof SearchRequest => new SearchResultDone(
                $resultCode,
                $dn,
                $diagnostic,
            ),
            $request instanceof AddRequest => new AddResponse(
                $resultCode,
                $dn,
                $diagnostic,
            ),
            $request instanceof CompareRequest => new CompareResponse(
                $resultCode,
                $dn,
                $diagnostic,
            ),
            $request instanceof DeleteRequest => new DeleteResponse(
                $resultCode,
                $dn,
                $diagnostic,
            ),
            $request instanceof ModifyDnRequest => new ModifyDnResponse(
                $resultCode,
                $dn,
                $diagnostic,
            ),
            $request instanceof ModifyRequest => new ModifyResponse(
                $resultCode,
                $dn,
                $diagnostic,
            ),
            $request instanceof ExtendedRequest => new ExtendedResponse(
                new LdapResult(
                    $resultCode,
                    $dn,
                    $diagnostic,
                ),
                $request->getName(),
            ),
            default => null,
        };

        if ($response === null) {
            return $this->getExtendedError(
                'Invalid request.',
                ResultCode::OPERATIONS_ERROR,
            );
        }

        return new LdapMessageResponse(
            $message->getMessageId(),
            $response,
        );
    }

    /**
     * Retrieve an extended error, which has a message ID of zero.
     */
    public function getExtendedError(
        string $message,
        int $errorCode,
        ?string $responseName = null,
    ): LdapMessageResponse {
        return new LdapMessageResponse(
            0,
            new ExtendedResponse(
                new LdapResult(
                    $errorCode,
                    '',
                    $message,
                ),
                $responseName,
            ),
        );
    }
}
