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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal\Change;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;

/**
 * A change handed to the journal for appending; the journal assigns the seq, origin, and timestamp.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PendingChange
{
    public function __construct(
        public ChangeType $changeType,
        public Dn $dn,
        public string $entryUuid,
        public AuthzId $authzId,
        public ?Dn $previousDn = null,
        public ?Entry $preImage = null,
    ) {}
}
