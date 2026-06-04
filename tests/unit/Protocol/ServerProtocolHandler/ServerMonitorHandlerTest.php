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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerMonitorHandler;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Metrics\Observation\OperationObservation;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\ServerRunner\PcntlServerRunner;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerMonitorHandlerTest extends TestCase
{
    private ServerQueue&MockObject $mockQueue;

    private TokenInterface&MockObject $mockToken;

    private InMemoryMetricsRecorder $metrics;

    private ServerMonitorHandler $subject;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->metrics = new InMemoryMetricsRecorder();

        $this->subject = new ServerMonitorHandler(
            options: new ServerOptions(),
            queue: $this->mockQueue,
            snapshots: $this->metrics,
        );
    }

    public function test_it_serves_the_cn_monitor_entry(): void
    {
        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                self::callback(static function (LdapMessageResponse $response): bool {
                    /** @var SearchResultEntry $result */
                    $result = $response->getResponse();
                    $entry = $result->getEntry();

                    return $entry->getDn()->toString() === 'cn=monitor'
                        && ($entry->get('objectClass')?->has('extensibleObject') ?? false);
                }),
                self::equalTo(new LdapMessageResponse(
                    1,
                    new SearchResultDone(ResultCode::SUCCESS),
                )),
            );

        $this->subject->handleRequest(
            $this->makeMessage(),
            $this->mockToken,
        );
    }

    public function test_it_reports_the_live_connection_gauges(): void
    {
        $this->metrics->connectionObserved(ConnectionObservation::Opened);
        $this->metrics->connectionObserved(ConnectionObservation::Opened);
        $this->metrics->connectionObserved(ConnectionObservation::Closed);

        $entry = $this->handleAndCaptureEntry();

        self::assertSame(
            ['1'],
            $entry->get('connectionsActive')?->getValues(),
        );
        self::assertSame(
            ['2'],
            $entry->get('connectionsTotal')?->getValues(),
        );
    }

    public function test_it_reports_operation_totals_and_a_per_type_breakdown(): void
    {
        $this->metrics->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.1,
            ResultCode::SUCCESS,
        ));
        $this->metrics->operationObserved(new OperationObservation(
            OperationType::Search,
            false,
            0.1,
            ResultCode::NO_SUCH_OBJECT,
        ));

        $entry = $this->handleAndCaptureEntry();

        self::assertSame(
            ['2'],
            $entry->get('operationsCompleted')?->getValues(),
        );
        self::assertSame(
            ['1'],
            $entry->get('operationsFailed')?->getValues(),
        );
        self::assertSame(
            ['search=2'],
            $entry->get('operationsByType')?->getValues(),
        );
    }

    public function test_it_reports_the_server_host(): void
    {
        $host = gethostname();

        if ($host === false) {
            self::markTestSkipped('gethostname() is unavailable on this system.');
        }

        $entry = $this->handleAndCaptureEntry();

        self::assertSame(
            [$host],
            $entry->get('serverHost')?->getValues(),
        );
    }

    public function test_it_reports_the_runner_class(): void
    {
        $entry = $this->handleAndCaptureEntry();

        self::assertSame(
            [PcntlServerRunner::class],
            $entry->get('serverRunner')?->getValues(),
        );
    }

    public function test_it_omits_the_start_time_when_unknown(): void
    {
        $entry = $this->handleAndCaptureEntry();

        self::assertNull($entry->get('serverStartTime'));
        self::assertNull($entry->get('serverUptimeSeconds'));
    }

    private function makeMessage(): LdapMessageRequest
    {
        return new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))
                ->base('cn=monitor')
                ->useBaseScope(),
        );
    }

    private function handleAndCaptureEntry(): Entry
    {
        $captured = null;

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with(
                self::callback(static function (LdapMessageResponse $response) use (&$captured): bool {
                    /** @var SearchResultEntry $result */
                    $result = $response->getResponse();
                    $captured = $result->getEntry();

                    return true;
                }),
                self::anything(),
            );

        $this->subject->handleRequest(
            $this->makeMessage(),
            $this->mockToken,
        );

        assert($captured instanceof Entry);

        return $captured;
    }
}
