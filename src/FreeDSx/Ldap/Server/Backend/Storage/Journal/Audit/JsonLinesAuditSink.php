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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;

/**
 * Appends each record as one JSON line, redacting the pre-image; appends are lock-guarded for multi-process safety.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class JsonLinesAuditSink implements AuditSinkInterface
{
    private AuditRedaction $redaction;

    public function __construct(
        private string $path,
        ?AuditRedaction $redaction = null,
    ) {
        $this->redaction = $redaction ?? AuditRedaction::default();
    }

    public function write(ChangeRecord $record): void
    {
        $data = $record->toArray();

        // Redact at the export boundary: overwrite the full pre-image with a redacted projection.
        if ($record->change->preImage !== null) {
            $data['pre_image'] = $this->redaction->apply($record->change->preImage);
        }

        $line = json_encode(
            $data,
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        ) . "\n";

        if (file_put_contents($this->path, $line, FILE_APPEND | LOCK_EX) === false) {
            throw new RuntimeException('Failed to write a record to the audit sink.');
        }
    }
}
