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

use FreeDSx\Ldap\Server\Metrics\Snapshot\OperationMetrics;
use FreeDSx\Ldap\Server\Process\ChannelMessage;

/**
 * Carries a child process's operation-metrics delta to the parent over a ChildChannel.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class OperationDeltaMessage implements ChannelMessage
{
    public function __construct(private OperationMetrics $operations) {}

    public function operations(): OperationMetrics
    {
        return $this->operations;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->operations->toArray();
    }
}
