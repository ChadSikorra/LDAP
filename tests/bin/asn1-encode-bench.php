<?php

declare(strict_types=1);

/**
 * Microbenchmark driver for the SearchResultEntry ASN.1 encode/decode hot path.
 *
 * Compares the current path (toAsn1()/fromAsn1() + LdapEncoder over the generic
 * AbstractType tree) against a direct Entry<->bytes fast-path prototype, and reports
 * ops/sec, ns/entry, and peak memory. Re-execs with tracing JIT enabled by default
 * (shared bench_bootstrap); pass --no-jit for an interpreter-mode baseline. Run with
 * --help to see the corpus options.
 */

use Symfony\Component\Console\Application;
use Tests\Performance\FreeDSx\Ldap\Asn1\Asn1EncodeBenchCommand;

require __DIR__ . '/internals/bench_bootstrap.php';
require __DIR__ . '/../../vendor/autoload.php';

$command = new Asn1EncodeBenchCommand();
$application = new Application('FreeDSx LDAP asn1-encode-bench');
$application->add($command);
$application->setDefaultCommand(
    (string) $command->getName(),
    true,
);
$application->run();
