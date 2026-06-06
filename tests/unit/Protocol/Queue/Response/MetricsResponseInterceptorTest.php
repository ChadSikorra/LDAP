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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Queue\Response;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\MetricsResponseInterceptor;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use PHPUnit\Framework\TestCase;

final class MetricsResponseInterceptorTest extends TestCase
{
    private InMemoryMetricsRecorder $recorder;

    private MetricsResponseInterceptor $subject;

    protected function setUp(): void
    {
        $this->recorder = new InMemoryMetricsRecorder();
        $this->subject = new MetricsResponseInterceptor($this->recorder);
    }

    public function test_it_counts_a_search_result_entry(): void
    {
        $response = new LdapMessageResponse(
            1,
            new SearchResultEntry(new Entry('cn=foo,dc=bar')),
        );

        $returned = $this->subject->intercept($response);

        self::assertSame(
            $response,
            $returned,
        );
        self::assertSame(
            1,
            $this->recorder->snapshot()->traffic->entriesReturned,
        );
    }

    public function test_it_does_not_count_a_non_entry_response(): void
    {
        $this->subject->intercept(new LdapMessageResponse(
            1,
            new SearchResultDone(ResultCode::SUCCESS),
        ));

        self::assertSame(
            0,
            $this->recorder->snapshot()->traffic->entriesReturned,
        );
    }
}
