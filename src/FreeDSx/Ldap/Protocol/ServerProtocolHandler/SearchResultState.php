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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;

/**
 * Late-bound result code / diagnostic for a streaming search.
 */
final class SearchResultState
{
    public bool $isAbandoned = false;

    public ?LdapMessageRequest $cancelSignal = null;

    public int $entriesReturned = 0;

    public function __construct(
        public int $resultCode = ResultCode::SUCCESS,
        public string $diagnosticMessage = '',
    ) {}
}
