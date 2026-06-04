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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Metrics\MetricsSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\Snapshot\MetricsSnapshot;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use FreeDSx\Ldap\Server\ServerRunner\PcntlServerRunner;
use FreeDSx\Ldap\Server\ServerRunner\SwooleServerRunner;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;

use function array_filter;
use function gethostname;
use function gmdate;
use function max;
use function time;

/**
 * Serves the server-generated cn=monitor entry from the current metrics snapshot.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerMonitorHandler implements ServerProtocolHandlerInterface
{
    public const DN = 'cn=monitor';

    public function __construct(
        private readonly ServerOptions $options,
        private readonly ServerQueue $queue,
        private readonly MetricsSnapshotProvider $snapshots,
    ) {}

    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): OperationResult {
        $entry = Entry::fromArray(
            self::DN,
            $this->attributes($this->snapshots->snapshot()),
        );

        $this->queue->sendMessage(
            new LdapMessageResponse(
                $message->getMessageId(),
                new SearchResultEntry($entry),
            ),
            new LdapMessageResponse(
                $message->getMessageId(),
                new SearchResultDone(ResultCode::SUCCESS),
            ),
        );

        return OperationOutcomeResult::succeeded();
    }

    /**
     * @return array<string, list<string>>
     */
    private function attributes(MetricsSnapshot $snapshot): array
    {
        $lifecycle = $snapshot->lifecycle;
        $connections = $snapshot->connections;
        $operations = $snapshot->operations;

        return array_filter([
            'objectClass' => ['top', 'extensibleObject'],
            'cn' => ['monitor'],
            'serverHost' => $this->serverHost(),
            'serverVersion' => $this->optionalString($this->options->getDseVendorVersion()),
            'serverRunner' => [$this->runnerClass()],
            'serverStartTime' => $this->generalizedTime($lifecycle->startedAt),
            'serverUptimeSeconds' => $this->uptimeSeconds($lifecycle->startedAt),
            'configReloadCount' => [(string) $lifecycle->reloadCount],
            'configReloadTime' => $this->generalizedTime($lifecycle->lastReloadAt),
            'connectionsActive' => [(string) $connections->active],
            'connectionsTotal' => [(string) $connections->total],
            'connectionsRejected' => [(string) $connections->rejected],
            'connectionsWriteTimeouts' => [(string) $connections->writeTimeouts],
            'connectionsIdleTimeouts' => [(string) $connections->idleTimeouts],
            'connectionsMax' => [(string) $this->options->getMaxConnections()],
            'operationsCompleted' => [(string) $operations->total()],
            'operationsFailed' => [(string) $operations->totalErrors()],
            'operationsByType' => $this->operationsByType($operations->counts),
        ]);
    }

    /**
     * @return list<string>
     */
    private function serverHost(): array
    {
        $host = gethostname();

        if ($host === false) {
            return [];
        }

        return [$host];
    }

    /**
     * The configured runner's class, falling back to the built-in default selected by the swoole flag.
     */
    private function runnerClass(): string
    {
        $runner = $this->options->getServerRunner();

        if ($runner !== null) {
            return $runner::class;
        }

        return $this->options->getUseSwooleRunner()
            ? SwooleServerRunner::class
            : PcntlServerRunner::class;
    }

    /**
     * @param array<string, int> $counts
     * @return list<string>
     */
    private function operationsByType(array $counts): array
    {
        $values = [];

        foreach ($counts as $operation => $count) {
            $values[] = $operation . '=' . $count;
        }

        return $values;
    }

    /**
     * @return list<string>
     */
    private function generalizedTime(int $timestamp): array
    {
        if ($timestamp <= 0) {
            return [];
        }

        return [gmdate('YmdHis\\Z', $timestamp)];
    }

    /**
     * @return list<string>
     */
    private function uptimeSeconds(int $startedAt): array
    {
        if ($startedAt <= 0) {
            return [];
        }

        return [(string) max(
            0,
            time() - $startedAt,
        )];
    }

    /**
     * @return list<string>
     */
    private function optionalString(?string $value): array
    {
        if ($value === null) {
            return [];
        }

        return [$value];
    }
}
