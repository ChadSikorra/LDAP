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

namespace FreeDSx\Ldap\Server\Metrics\Rollup;

use FreeDSx\Ldap\Server\Process\ChannelMessageFactory;
use FreeDSx\Ldap\Server\Process\ChildChannel;

/**
 * Moves child operation metrics to the parent over a ChildChannel.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class OperationRollupCoordinator
{
    private ?ChildChannel $boundChannel = null;

    public function __construct(
        private readonly MetricsRollupInterface $recorder,
        private readonly ChannelMessageFactory $messageFactory = new MetricsDeltaMessageFactory(),
    ) {}

    public function openChannel(): ChildChannel
    {
        return ChildChannel::create($this->messageFactory);
    }

    /**
     * In the child: clear metrics inherited from the parent and bind the channel this child reports on.
     */
    public function enterChild(ChildChannel $channel): void
    {
        $this->recorder->resetDelta();
        $this->boundChannel = $channel;
    }

    /**
     * In the child: report the metrics recorded since the last flush.
     */
    public function flush(): void
    {
        $this->boundChannel?->send(new MetricsDeltaMessage($this->recorder->takeDelta()));
    }

    /**
     * In the child: send a final flush, then close the write end so the parent reads EOF.
     */
    public function finish(): void
    {
        $this->flush();
        $this->boundChannel?->closeWrite();
    }

    /**
     * In the parent: fold any metrics deltas available on a child's channel into the totals.
     */
    public function collect(ChildChannel $channel): void
    {
        foreach ($channel->receive() as $message) {
            if ($message instanceof MetricsDeltaMessage) {
                $this->recorder->mergeDelta($message->delta());
            }
        }
    }
}
