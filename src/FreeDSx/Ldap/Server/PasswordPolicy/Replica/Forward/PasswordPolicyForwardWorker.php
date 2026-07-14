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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Replica\Forward;

use FreeDSx\Ldap\Operation\Request\ForwardPasswordPolicyStateRequest;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaForwardState;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;

/**
 * Drains the replica-local password-policy forward queue and delivers each pending subject's state to the primary.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class PasswordPolicyForwardWorker
{
    public function __construct(
        private ReplicaPasswordStateStoreInterface $store,
        private ForwardStateSenderInterface $sender,
        private int $batchLimit = 100,
    ) {}

    /**
     * Forward every pending subject in watermark order, advancing the watermark after each successful delivery; a
     * delivery failure stops the drain so the remainder stays pending for the next run.
     *
     * @return int the number of subjects forwarded
     */
    public function forwardOnce(): int
    {
        $forwarded = 0;

        foreach ($this->store->listUnforwarded($this->batchLimit) as $pending) {
            $this->sender->send($this->requestFor($pending));
            $this->store->markForwarded(
                $pending->dn,
                $pending->sequence,
            );
            ++$forwarded;
        }

        return $forwarded;
    }

    private function requestFor(ReplicaForwardState $pending): ForwardPasswordPolicyStateRequest
    {
        $state = $pending->state->toUserPasswordState($pending->dn);

        return new ForwardPasswordPolicyStateRequest(
            $pending->dn,
            failureTimes: $state->failureTimes,
            lastSuccess: $state->lastSuccess,
        );
    }
}
