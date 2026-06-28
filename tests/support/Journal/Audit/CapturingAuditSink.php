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

namespace Tests\Support\FreeDSx\Ldap\Journal\Audit;

use FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit\AuditSinkInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;

/**
 * Audit sink that retains every written record for assertions.
 */
final class CapturingAuditSink implements AuditSinkInterface
{
    /**
     * @var list<ChangeRecord>
     */
    public array $written = [];

    public function write(ChangeRecord $record): void
    {
        $this->written[] = $record;
    }
}
