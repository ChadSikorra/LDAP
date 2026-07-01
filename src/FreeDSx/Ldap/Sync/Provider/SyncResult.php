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

namespace FreeDSx\Ldap\Sync\Provider;

use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;

/**
 * A projected sync entry and its state control, before the message envelope is attached.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SyncResult
{
    public function __construct(
        public SearchResultEntry $entry,
        public SyncStateControl $control,
    ) {}
}
