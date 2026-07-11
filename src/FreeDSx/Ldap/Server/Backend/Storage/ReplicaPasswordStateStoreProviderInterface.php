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

namespace FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Server\PasswordPolicy\Replica\ReplicaPasswordStateStoreInterface;

/**
 * A storage adapter that can vend a persistent replica-local password-policy state store.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ReplicaPasswordStateStoreProviderInterface
{
    /**
     * The replica-local password-policy state store backed by this adapter's connection.
     */
    public function replicaPasswordStateStore(): ReplicaPasswordStateStoreInterface;
}
