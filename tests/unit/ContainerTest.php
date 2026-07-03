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

namespace Tests\Unit\FreeDSx\Ldap;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\Factory\ClientProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ClientQueueInstantiator;
use FreeDSx\Ldap\Protocol\RootDseLoader;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\Metrics\File\FileSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\MetricsSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Recorder\MetricsRecorderChain;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Ldap\Server\ServerProtocolFactory;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\Server\SocketServerFactory;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\SocketPool;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class ContainerTest extends TestCase
{
    private Container $subject;

    protected function setUp(): void
    {
        parent::setUp();

        $client = new LdapClient();
        $serverOptions = (new ServerOptions())->useInMemoryStorage();

        $this->subject = new Container([
            LdapClient::class => $client,
            ClientOptions::class => $client->getOptions(),
            ServerOptions::class => $serverOptions,
        ]);
    }

    public function test_it_assembles_the_backend_from_the_configured_storage(): void
    {
        self::assertInstanceOf(
            WritableStorageBackend::class,
            $this->subject->get(HandlerFactoryInterface::class)->makeBackend(),
        );
    }

    /**
     * @return array<array{class-string}>
     */
    public static function buildableDependenciesDataProvider(): array
    {
        return [
            [LdapClient::class],
            [ClientProtocolHandler::class],
            [ClientQueueInstantiator::class],
            [ClientProtocolHandlerFactory::class],
            [SocketPool::class],
            [RootDseLoader::class],
            [ServerProtocolFactory::class],
            [HandlerFactoryInterface::class],
            [ServerAuthorization::class],
            [SocketServerFactory::class],
            [MetricsRecorderInterface::class],
            [MetricsSnapshotProvider::class],
            [InMemoryMetricsRecorder::class],
        ];
    }

    /**
     * @param class-string $class
     */
    #[DataProvider('buildableDependenciesDataProvider')]
    public function test_it_builds_the_dependencies(
        string $class,
    ): void {
        self::assertInstanceOf(
            $class,
            $this->subject->get($class),
        );
    }

    public function test_it_should_make_the_default_ServerRunner(): void
    {
        if (str_starts_with(strtoupper(PHP_OS), 'WIN')) {
            self::markTestSkipped('Cannot construct the default PCNTL runner on Windows.');
        }

        self::assertInstanceOf(
            ServerRunnerInterface::class,
            $this->subject->get(ServerRunnerInterface::class),
        );
    }

    public function test_the_metrics_recorder_is_a_no_op_when_monitor_is_disabled(): void
    {
        self::assertInstanceOf(
            NullMetricsRecorder::class,
            $this->subject->get(MetricsRecorderInterface::class),
        );
    }

    public function test_the_metrics_recorder_is_in_memory_when_monitor_is_enabled(): void
    {
        $container = $this->containerFor((new ServerOptions())->setMonitorEnabled(true));

        self::assertInstanceOf(
            InMemoryMetricsRecorder::class,
            $container->get(MetricsRecorderInterface::class),
        );
    }

    public function test_the_metrics_recorder_chains_a_user_recorder_when_one_is_set(): void
    {
        $container = $this->containerFor(
            (new ServerOptions())
                ->setMonitorEnabled(true)
                ->setMetricsRecorder(new InMemoryMetricsRecorder()),
        );

        self::assertInstanceOf(
            MetricsRecorderChain::class,
            $container->get(MetricsRecorderInterface::class),
        );
    }

    public function test_the_snapshot_provider_is_the_live_recorder_under_swoole(): void
    {
        $container = $this->containerFor(
            (new ServerOptions())
                ->setMonitorEnabled(true)
                ->setUseSwooleRunner(true),
        );

        self::assertSame(
            $container->get(MetricsRecorderInterface::class),
            $container->get(MetricsSnapshotProvider::class),
        );
    }

    public function test_the_snapshot_provider_is_file_based_under_pcntl(): void
    {
        $container = $this->containerFor((new ServerOptions())->setMonitorEnabled(true));

        self::assertInstanceOf(
            FileSnapshotProvider::class,
            $container->get(MetricsSnapshotProvider::class),
        );
    }

    private function containerFor(ServerOptions $options): Container
    {
        return new Container([
            ServerOptions::class => $options->useInMemoryStorage(),
        ]);
    }
}
