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

namespace FreeDSx\Ldap\Server\Metrics\Snapshot;

use function array_sum;

/**
 * Operation metrics: counts, failures, and latency by operation, plus a result-code breakdown.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class OperationMetrics
{
    /**
     * @param array<string, int> $counts Operation label to total count.
     * @param array<string, int> $errors Operation label to failed count.
     * @param array<string, float> $durationSeconds Operation label to summed duration.
     * @param array<int, int> $resultCodeCounts LDAP result code to count.
     * @param array<string, int> $bindCounts Bind sub-type (anonymous/simple/sasl) to count.
     * @param array<string, int> $searchScopeCounts Search scope (base/one/sub) to count.
     */
    public function __construct(
        public array $counts = [],
        public array $errors = [],
        public array $durationSeconds = [],
        public array $resultCodeCounts = [],
        public array $bindCounts = [],
        public array $searchScopeCounts = [],
    ) {}

    public function total(): int
    {
        return array_sum($this->counts);
    }

    public function totalErrors(): int
    {
        return array_sum($this->errors);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'counts' => $this->counts,
            'errors' => $this->errors,
            'duration_seconds' => $this->durationSeconds,
            'result_code_counts' => $this->resultCodeCounts,
            'bind_counts' => $this->bindCounts,
            'search_scope_counts' => $this->searchScopeCounts,
        ];
    }

    /**
     * @param array<array-key, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            counts: SnapshotValue::toIntMap($data['counts'] ?? null),
            errors: SnapshotValue::toIntMap($data['errors'] ?? null),
            durationSeconds: SnapshotValue::toFloatMap($data['duration_seconds'] ?? null),
            resultCodeCounts: SnapshotValue::toIntKeyedIntMap($data['result_code_counts'] ?? null),
            bindCounts: SnapshotValue::toIntMap($data['bind_counts'] ?? null),
            searchScopeCounts: SnapshotValue::toIntMap($data['search_scope_counts'] ?? null),
        );
    }
}
