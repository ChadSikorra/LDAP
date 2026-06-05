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
final readonly class OperationRollupCoordinator
{
    public function __construct(
        private OperationRollupInterface $recorder,
        private ChannelMessageFactory $messageFactory = new OperationDeltaMessageFactory(),
    ) {}

    public function openChannel(): ChildChannel
    {
        return ChildChannel::create($this->messageFactory);
    }

    /**
     * Clear the operations inherited from the parent so a fresh child reports only its own.
     */
    public function startChild(): void
    {
        $this->recorder->resetOperations();
    }

    /**
     * Send this child's operation delta to the parent, then close the write end so the parent reads EOF.
     */
    public function reportChild(ChildChannel $channel): void
    {
        $channel->send(new OperationDeltaMessage($this->recorder->takeOperationDelta()));
        $channel->closeWrite();
    }

    /**
     * Fold any operation deltas a reaped child reported into the parent totals.
     */
    public function collect(ChildChannel $channel): void
    {
        foreach ($channel->receive() as $message) {
            if ($message instanceof OperationDeltaMessage) {
                $this->recorder->mergeOperations($message->operations());
            }
        }
    }
}
