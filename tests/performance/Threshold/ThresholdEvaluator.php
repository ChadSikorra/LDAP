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

namespace Tests\Performance\FreeDSx\Ldap\Threshold;

use Tests\Performance\FreeDSx\Ldap\Stats\StatsSnapshot;

/**
 * Compares a StatsSnapshot against a ThresholdSet and reports pass/fail per gate.
 */
final class ThresholdEvaluator
{
    public function evaluate(
        StatsSnapshot $snapshot,
        ThresholdSet $thresholds,
    ): ThresholdResult {
        $gates = [];

        if ($thresholds->maxErrors !== null) {
            $gates[] = $this->evaluateMaxErrors(
                $snapshot,
                $thresholds->maxErrors,
            );
        }

        if ($thresholds->maxErrorRate !== null) {
            $gates[] = $this->evaluateMaxErrorRate(
                $snapshot,
                $thresholds->maxErrorRate,
            );
        }

        if ($thresholds->minThroughput !== null) {
            $gates[] = $this->evaluateMinThroughput(
                $snapshot,
                $thresholds->minThroughput,
            );
        }

        if ($thresholds->maxP99Ms !== null || $thresholds->perOpMaxP99Ms !== []) {
            $gates[] = $this->evaluateMaxP99(
                $snapshot,
                $thresholds->maxP99Ms,
                $thresholds->perOpMaxP99Ms,
            );
        }

        $passed = true;
        foreach ($gates as $gate) {
            if ($gate['passed']) {
                continue;
            }

            $passed = false;
            break;
        }

        return new ThresholdResult($passed, $gates);
    }

    /**
     * @return array{gate: string, passed: bool, expected: string, actual: string}
     */
    private function evaluateMaxErrors(
        StatsSnapshot $snapshot,
        int $maxErrors,
    ): array {
        $errors = $snapshot->totalErrors();

        return [
            'gate' => 'max-errors',
            'passed' => $errors <= $maxErrors,
            'expected' => sprintf('<= %d', $maxErrors),
            'actual' => (string) $errors,
        ];
    }

    /**
     * @return array{gate: string, passed: bool, expected: string, actual: string}
     */
    private function evaluateMaxErrorRate(
        StatsSnapshot $snapshot,
        float $maxRate,
    ): array {
        $attempts = $snapshot->totalSuccess() + $snapshot->totalErrors();
        $rate = $attempts > 0
            ? $snapshot->totalErrors() / $attempts
            : 0.0;

        return [
            'gate' => 'max-error-rate',
            'passed' => $rate <= $maxRate,
            'expected' => sprintf('<= %.6f', $maxRate),
            'actual' => sprintf('%.6f', $rate),
        ];
    }

    /**
     * @return array{gate: string, passed: bool, expected: string, actual: string}
     */
    private function evaluateMinThroughput(
        StatsSnapshot $snapshot,
        float $minOps,
    ): array {
        $tput = $snapshot->overallThroughput();

        return [
            'gate' => 'min-throughput',
            'passed' => $tput >= $minOps,
            'expected' => sprintf('>= %.2f ops/s', $minOps),
            'actual' => sprintf('%.2f ops/s', $tput),
        ];
    }

    /**
     * Gates each op against its own ceiling (per-op override, else the global), reporting the op nearest its limit.
     *
     * @param array<string, float> $perOpMaxMs
     *
     * @return array{gate: string, passed: bool, expected: string, actual: string}
     */
    private function evaluateMaxP99(
        StatsSnapshot $snapshot,
        ?float $globalMaxMs,
        array $perOpMaxMs,
    ): array {
        $worstOp = null;
        $worstRatio = 0.0;
        $worstP99Ms = 0.0;
        $worstCeilingMs = 0.0;

        foreach ($snapshot->operations() as $op) {
            $ceilingMs = $perOpMaxMs[$op] ?? $globalMaxMs;

            if ($ceilingMs === null) {
                continue;
            }

            $p99Ms = $snapshot->latencyStats($op)['p99'] / 1_000_000;
            $ratio = $p99Ms / $ceilingMs;

            if ($ratio <= $worstRatio) {
                continue;
            }

            $worstRatio = $ratio;
            $worstOp = $op;
            $worstP99Ms = $p99Ms;
            $worstCeilingMs = $ceilingMs;
        }

        return [
            'gate' => 'max-p99-ms',
            'passed' => $worstOp === null || $worstP99Ms <= $worstCeilingMs,
            'expected' => $worstOp !== null
                ? sprintf('<= %.2f ms (%s)', $worstCeilingMs, $worstOp)
                : 'no gated ops',
            'actual' => $worstOp !== null
                ? sprintf('%.2f ms (%s)', $worstP99Ms, $worstOp)
                : 'no data',
        ];
    }
}
