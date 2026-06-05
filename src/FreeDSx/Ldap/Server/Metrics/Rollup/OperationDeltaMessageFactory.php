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
use FreeDSx\Ldap\Server\Process\ChannelMessageFactory;

/**
 * Rebuilds an OperationDeltaMessage from its wire form on the parent's end of a ChildChannel.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class OperationDeltaMessageFactory implements ChannelMessageFactory
{
    /**
     * @param array<array-key, mixed> $data
     */
    public function fromArray(array $data): ChannelMessage
    {
        return new OperationDeltaMessage(OperationMetrics::fromArray($data));
    }
}
