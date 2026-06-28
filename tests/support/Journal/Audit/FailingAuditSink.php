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
use RuntimeException;
use Throwable;

/**
 * Audit sink that always throws, for exercising sink-failure handling.
 */
final class FailingAuditSink implements AuditSinkInterface
{
    public function __construct(
        private readonly Throwable $error = new RuntimeException('the audit sink is unavailable'),
    ) {}

    public function write(ChangeRecord $record): void
    {
        throw $this->error;
    }
}
