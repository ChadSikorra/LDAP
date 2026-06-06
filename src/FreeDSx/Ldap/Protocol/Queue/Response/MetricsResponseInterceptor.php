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

namespace FreeDSx\Ldap\Protocol\Queue\Response;

use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\Observation\TrafficObservation;

/**
 * Counts search-result entries as they stream out to the client.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class MetricsResponseInterceptor implements ResponseInterceptor
{
    public function __construct(private MetricsRecorderInterface $recorder) {}

    public function intercept(LdapMessageResponse $response): LdapMessageResponse
    {
        if ($response->getResponse() instanceof SearchResultEntry) {
            $this->recorder->trafficObserved(new TrafficObservation(entriesReturned: 1));
        }

        return $response;
    }
}
