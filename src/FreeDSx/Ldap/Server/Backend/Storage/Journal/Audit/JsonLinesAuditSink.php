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
 * Envelope fields (dn, entry_uuid, authz_id, timestamps) are plain UTF-8; pre_image values are base64 and must be
 * decoded by a consumer.
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

        // Redact at the export boundary, then base64 every value: pre_image is the only
        // binary-capable field, so uniform encoding keeps the record valid JSON with one value shape.
        if ($record->change->preImage !== null) {
            $data['pre_image'] = $this->encodeValues(
                $this->redaction->apply($record->change->preImage),
            );
        }

        $line = json_encode(
            $data,
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        ) . "\n";

        if (file_put_contents($this->path, $line, FILE_APPEND | LOCK_EX) === false) {
            throw new RuntimeException('Failed to write a record to the audit sink.');
        }
    }

    /**
     * Base64-encodes every attribute value so a binary value (e.g. a certificate) is captured
     * faithfully rather than aborting the encode and dropping the record.
     *
     * @param array<string, list<string>> $attributes
     * @return array<string, list<string>>
     */
    private function encodeValues(array $attributes): array
    {
        return array_map(
            static fn(array $values): array => array_map(
                base64_encode(...),
                $values,
            ),
            $attributes,
        );
    }
}
