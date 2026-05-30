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

namespace Tests\Support\FreeDSx\Ldap\Protocol\Queue\Response;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseInterceptor;
use Tests\Support\FreeDSx\Ldap\Middleware\CallLog;

/**
 * Records its marker for ordering assertions and attaches a marker control so transformation is observable.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class RecordingInterceptor implements ResponseInterceptor
{
    public function __construct(
        private CallLog $log,
        private string $marker,
    ) {}

    public function intercept(LdapMessageResponse $response): LdapMessageResponse
    {
        $this->log->record($this->marker);
        $response->controls()->add(new Control($this->marker));

        return $response;
    }
}
