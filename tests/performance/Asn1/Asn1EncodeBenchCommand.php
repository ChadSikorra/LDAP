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

namespace Tests\Performance\FreeDSx\Ldap\Asn1;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use RuntimeException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

use function array_map;
use function array_sum;
use function bin2hex;
use function count;
use function function_exists;
use function hrtime;
use function ini_get;
use function is_array;
use function max;
use function memory_get_peak_usage;
use function mt_rand;
use function mt_srand;
use function number_format;
use function opcache_get_status;
use function pack;
use function sprintf;
use function str_pad;
use function str_repeat;
use function strlen;
use function substr;

/**
 * Microbenchmark for the SearchResultEntry ASN.1 encode/decode hot path.
 *
 * Times four pipelines over a generated corpus and prints a comparison:
 *   encode-current   SearchResultEntry::toAsn1() -> LdapEncoder::encode()
 *   encode-fastpath  SearchResultEntryCodec::encode()      (direct, no AbstractType tree)
 *   decode-current   LdapEncoder::decode() -> SearchResultEntry::fromAsn1()
 *   decode-fastpath  SearchResultEntryCodec::decode()      (direct cursor reader)
 *
 * A correctness gate runs first: the fast-path encode must be byte-identical to the
 * production encoder, and the fast-path decode must produce an equal entry. The
 * numbers are meaningless otherwise, so a mismatch aborts the run.
 *
 * JIT note: the bin (asn1-encode-bench.php) re-execs with tracing JIT on by default via
 * the shared bench_bootstrap. Pass --no-jit for an interpreter-mode baseline. The active
 * JIT state is printed in the header so the two runs are labelled.
 */
final class Asn1EncodeBenchCommand extends Command
{
    protected static $defaultName = 'asn1-encode-bench';

    protected static $defaultDescription = 'Benchmark SearchResultEntry ASN.1 encode/decode: current path vs a direct fast-path prototype.';

    /**
     * Corpus presets. "wide-attrs" looks like a typical directory entry dump (many small
     * attributes); "wide-values" stresses few attributes with large binary values.
     *
     * @var array<string, array{entries:int, attrs:int, values:int, size:int}>
     */
    private const PROFILES = [
        'wide-attrs' => ['entries' => 1000, 'attrs' => 15, 'values' => 3, 'size' => 32],
        'wide-values' => ['entries' => 200, 'attrs' => 3, 'values' => 2, 'size' => 4096],
    ];

    protected function configure(): void
    {
        $this
            ->addOption('profile', null, InputOption::VALUE_REQUIRED, 'Corpus preset: wide-attrs | wide-values | custom', 'wide-attrs')
            ->addOption('entries', null, InputOption::VALUE_REQUIRED, 'Entries in the corpus (overrides preset)')
            ->addOption('attrs-per-entry', null, InputOption::VALUE_REQUIRED, 'Attributes per entry (overrides preset)')
            ->addOption('values-per-attr', null, InputOption::VALUE_REQUIRED, 'Values per attribute (overrides preset)')
            ->addOption('value-size', null, InputOption::VALUE_REQUIRED, 'Bytes per attribute value (overrides preset)')
            ->addOption('iterations', null, InputOption::VALUE_REQUIRED, 'Times the corpus is processed per pipeline', '20')
            // Consumed by bench_bootstrap before Symfony parses options; declared so the option is not rejected.
            ->addOption('no-jit', null, InputOption::VALUE_NONE, 'Run interpreted (handled by the bootstrap; shown here for --help)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $profileName = (string) $input->getOption('profile');
        $preset = self::PROFILES[$profileName] ?? self::PROFILES['wide-attrs'];

        $entries = (int) ($input->getOption('entries') ?? $preset['entries']);
        $attrs = (int) ($input->getOption('attrs-per-entry') ?? $preset['attrs']);
        $values = (int) ($input->getOption('values-per-attr') ?? $preset['values']);
        $size = (int) ($input->getOption('value-size') ?? $preset['size']);
        $iterations = max(1, (int) $input->getOption('iterations'));

        $output->writeln('<info>FreeDSx ASN.1 encode/decode microbenchmark</info>');
        $output->writeln(sprintf(
            'profile=%s  entries=%d  attrs/entry=%d  values/attr=%d  value-size=%dB  iterations=%d',
            $profileName,
            $entries,
            $attrs,
            $values,
            $size,
            $iterations,
        ));
        $output->writeln('jit: ' . $this->jitStatus());
        $output->writeln('');

        $encoder = new LdapEncoder();
        $corpus = $this->buildCorpus($entries, $attrs, $values, $size);

        // Pre-encode once for the decode pipelines, and as the byte-identical oracle.
        $encoded = [];
        foreach ($corpus as $i => $entry) {
            $encoded[$i] = $encoder->encode((new SearchResultEntry($entry))->toAsn1());
        }

        $this->assertCorrectness($encoder, $corpus, $encoded, $output);

        $totalOps = $entries * $iterations;
        $payloadBytes = array_sum(array_map('strlen', $encoded));
        $output->writeln(sprintf(
            'corpus encodes to %s per pass (%s total ops across pipelines)',
            $this->humanBytes($payloadBytes),
            number_format($totalOps),
        ));
        $output->writeln('');

        $encCurrent = $this->time(function () use ($corpus, $encoder): void {
            foreach ($corpus as $entry) {
                $encoder->encode((new SearchResultEntry($entry))->toAsn1());
            }
        }, $iterations);

        $encFast = $this->time(function () use ($corpus): void {
            foreach ($corpus as $entry) {
                SearchResultEntryCodec::encode($entry);
            }
        }, $iterations);

        $decCurrent = $this->time(function () use ($encoded, $encoder): void {
            foreach ($encoded as $bytes) {
                SearchResultEntry::fromAsn1($encoder->decode($bytes));
            }
        }, $iterations);

        $decFast = $this->time(function () use ($encoded): void {
            foreach ($encoded as $bytes) {
                SearchResultEntryCodec::decode($bytes);
            }
        }, $iterations);

        $this->renderTable($output, $totalOps, [
            ['encode-current', $encCurrent, null],
            ['encode-fastpath', $encFast, $encCurrent],
            ['decode-current', $decCurrent, null],
            ['decode-fastpath', $decFast, $decCurrent],
        ]);

        $output->writeln('');
        $output->writeln(sprintf('peak memory: %s', $this->humanBytes(memory_get_peak_usage(true))));

        return Command::SUCCESS;
    }

    /**
     * @return Entry[]
     */
    private function buildCorpus(int $entries, int $attrs, int $values, int $size): array
    {
        // Deterministic so runs are comparable; bytes vary so length-octet width varies too.
        mt_srand(1);
        $corpus = [];
        for ($e = 0; $e < $entries; $e++) {
            $attributes = [];
            for ($a = 0; $a < $attrs; $a++) {
                $vals = [];
                for ($v = 0; $v < $values; $v++) {
                    $vals[] = $this->randomBytes($size);
                }
                $attributes[] = Attribute::fromArray(sprintf('attr-%d', $a), $vals);
            }
            $corpus[] = Entry::raw(
                new Dn(sprintf('cn=user-%d,ou=people,dc=example,dc=com', $e)),
                $attributes,
            );
        }

        return $corpus;
    }

    private function randomBytes(int $size): string
    {
        $out = '';
        while (strlen($out) < $size) {
            $out .= bin2hex(pack('N', mt_rand()));
        }

        return substr($out, 0, $size);
    }

    /**
     * @param Entry[]  $corpus
     * @param string[] $encoded
     */
    private function assertCorrectness(LdapEncoder $encoder, array $corpus, array $encoded, OutputInterface $output): void
    {
        foreach ($corpus as $i => $entry) {
            $fastBytes = SearchResultEntryCodec::encode($entry);
            if ($fastBytes !== $encoded[$i]) {
                throw new RuntimeException(sprintf(
                    'Fast-path encode is NOT byte-identical for entry %d (%s).%scurrent:  %s%sfastpath: %s',
                    $i,
                    (string) $entry->getDn(),
                    PHP_EOL,
                    bin2hex($encoded[$i]),
                    PHP_EOL,
                    bin2hex($fastBytes),
                ));
            }

            $current = SearchResultEntry::fromAsn1($encoder->decode($encoded[$i]))->getEntry();
            $fast = SearchResultEntryCodec::decode($encoded[$i])->getEntry();
            if ($current != $fast || $current->toArray() !== $fast->toArray()
                || (string) $current->getDn() !== (string) $fast->getDn()) {
                throw new RuntimeException(sprintf(
                    'Fast-path decode produced a different entry for entry %d (%s).',
                    $i,
                    (string) $entry->getDn(),
                ));
            }
        }

        $output->writeln(sprintf(
            '<info>correctness gate passed</info>: fast-path encode byte-identical and decode equal for all %d entries',
            count($corpus),
        ));
    }

    /**
     * @return array{elapsed_ns: int|float}
     */
    private function time(callable $pass, int $iterations): array
    {
        $pass(); // warm caches / JIT trace

        $start = hrtime(true);
        for ($i = 0; $i < $iterations; $i++) {
            $pass();
        }
        $elapsedNs = hrtime(true) - $start;

        return ['elapsed_ns' => $elapsedNs];
    }

    /**
     * @param array<int, array{0:string, 1:array{elapsed_ns:int|float}, 2:?array{elapsed_ns:int|float}}> $rows
     */
    private function renderTable(OutputInterface $output, int $totalOps, array $rows): void
    {
        $output->writeln(sprintf(
            '%-18s %14s %14s %10s',
            'pipeline',
            'ops/sec',
            'ns/entry',
            'vs current',
        ));
        $output->writeln(str_repeat('-', 60));

        foreach ($rows as [$name, $result, $baseline]) {
            $ns = (float) $result['elapsed_ns'];
            $nsPerOp = $ns / $totalOps;
            $opsPerSec = $nsPerOp > 0 ? 1_000_000_000 / $nsPerOp : 0.0;

            $speedup = '-';
            if ($baseline !== null) {
                $ratio = (float) $baseline['elapsed_ns'] / max(1.0, $ns);
                $speedup = sprintf('%.2fx', $ratio);
            }

            $output->writeln(sprintf(
                '%-18s %14s %14s %10s',
                $name,
                number_format($opsPerSec),
                number_format($nsPerOp),
                $speedup,
            ));
        }
    }

    private function jitStatus(): string
    {
        if (function_exists('opcache_get_status')) {
            $status = @opcache_get_status(false);
            if (is_array($status) && isset($status['jit']['enabled'])) {
                return $status['jit']['enabled']
                    ? sprintf('ENABLED (buffer=%s)', $this->humanBytes((int) ($status['jit']['buffer_size'] ?? 0)))
                    : 'disabled';
            }
        }

        $jit = (string) ini_get('opcache.jit');

        return $jit === '' ? 'unknown' : sprintf('ini opcache.jit=%s', $jit);
    }

    private function humanBytes(int $bytes): string
    {
        $units = ['B', 'KiB', 'MiB', 'GiB'];
        $value = (float) $bytes;
        $unit = 0;
        while ($value >= 1024 && $unit < count($units) - 1) {
            $value /= 1024;
            $unit++;
        }

        return str_pad(sprintf('%.1f %s', $value, $units[$unit]), 1);
    }
}
