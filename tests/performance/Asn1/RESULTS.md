# ASN.1 Encoding Performance — Spike Results

This is the writeup for the empirical spike on the ASN.1 (BER) encode/decode hot path.
It quantifies two pure-PHP levers and records why FFI was rejected. **No `src/` behavior
was changed** — the fast-path here is a measured prototype (`SearchResultEntryCodec`) that
is *not* wired into the protocol layer.

Reproduce with:

```
composer bench-asn1                              # wide-attrs, JIT on
composer bench-asn1 -- --profile=wide-values     # large binary values, JIT on
composer bench-asn1 -- --no-jit                  # interpreter baseline
```

(`tests/bin/asn1-encode-bench.php` re-execs with tracing JIT by default via the shared
`bench_bootstrap`; `--no-jit` gives the interpreter baseline.)

## Where the time actually goes

The byte-level `BerEncoder` (`freedsx/asn1`) is already hand-tuned pure PHP
(`chr()`/`hex2bin()`/string concat, inlined `match`/`switch` with explicit "faster inline"
comments). The cost in the pipeline is not the byte work — it is:

1. **Allocating the intermediate `AbstractType` object graph.** `SearchResultEntry::toAsn1()`
   builds `N×M + ~5` small objects per entry (one `OctetStringType` per value, etc.).
2. **Per-node recursive `encode()` dispatch** walking that tree.
3. On decode, the mirror: `decode()` rebuilds the tree, then `fromAsn1()` walks it into
   `Entry`/`Attribute` — double allocation.

## Numbers

PHP 8.4.19, NTS, single core. One "op" = one `SearchResultEntry` encode or decode.
ns/entry is per-op; lower is better. `vs current` is the fast-path speedup over the
production path **within the same JIT mode**.

### wide-attrs — 1000 entries × 15 attrs × 3 values × 32B (typical directory dump)

| pipeline          | interpreter ops/sec | interpreter ns/entry | JIT ops/sec | JIT ns/entry | fast vs current (JIT) |
|-------------------|--------------------:|---------------------:|------------:|-------------:|----------------------:|
| encode-current    |              19,146 |               52,229 |      28,181 |       35,485 |                     — |
| encode-fastpath   |             101,446 |                9,857 |     140,748 |        7,105 |                 4.99× |
| decode-current    |              19,895 |               50,264 |      33,332 |       30,002 |                     — |
| decode-fastpath   |              47,818 |               20,912 |      85,275 |       11,727 |                 2.56× |

### wide-values — 200 entries × 3 attrs × 2 values × 4096B (large binary values)

| pipeline          | interpreter ops/sec | interpreter ns/entry | JIT ops/sec | JIT ns/entry | fast vs current (JIT) |
|-------------------|--------------------:|---------------------:|------------:|-------------:|----------------------:|
| encode-current    |              46,923 |               21,311 |      61,007 |       16,392 |                     — |
| encode-fastpath   |             121,177 |                8,252 |     147,039 |        6,801 |                 2.41× |
| decode-current    |              63,332 |               15,790 |      66,682 |       14,997 |                     — |
| decode-fastpath   |             139,161 |                7,186 |     134,146 |        7,455 |                 2.01× |

The fast-path output is **byte-identical** to the production encoder and decodes to an
**equal** `Entry` — the bench asserts this for every corpus entry before timing (correctness
gate), so the numbers are meaningful.

## Reading the results

**1. JIT is free throughput on the current path.** On `wide-attrs` the existing path goes
19,146 → 28,181 ops/sec on encode (≈1.47×) and 19,895 → 33,332 on decode (≈1.68×) just by
turning on tracing JIT — no code change. This branchy, arithmetic-heavy loop is exactly
tracing-JIT's sweet spot, and the server runners (Swoole/pcntl) are long-lived processes
that pay the warmup cost once. The CLI environment ships with `opcache.jit=Off` and
`opcache.enable_cli=Off` today, so this is currently left on the table for the server.

**2. The fast-path is the real win, and it scales with element count.** Skipping the
`AbstractType` tree is 2–5× on its own. The gain is largest on `wide-attrs` (many small
elements → many allocations/dispatches eliminated) and smaller on `wide-values` (2–2.5×),
where per-entry time is dominated by copying the large value bytes that **both** paths must
do. Combined with JIT, `wide-attrs` encode goes from 19,146 (current, interpreter) to
140,748 ops/sec (fast-path, JIT) — ≈**7.3×** end to end; decode ≈**4.3×**.

**3. This is exactly why FFI does not pay off.** The irreducible cost in the `wide-values`
case is the byte copy, which PHP already does at `zend_string` speed and C cannot beat. The
reducible cost is per-element object allocation/dispatch — and a coarse-grained FFI encoder
would have to *re-introduce* that per-element work to flatten PHP `Entry`/`Attribute`/value
objects into a C-consumable buffer, plus a cross-boundary copy. The slowdown just moves into
marshalling. The fast-path captures the same "kill the overhead" win **without** leaving
PHP, without `ext-ffi` (often disabled / needs preload outside CLI), and without shipping
per-platform native binaries — preserving the project's pure-PHP identity. If native speed
were ever genuinely required, a Zend extension or `ext-ldap` would dominate FFI anyway.

## Recommendation / next steps (gated on this data)

1. **Enable tracing JIT for the server runners** (`opcache.enable_cli=1`,
   `opcache.jit=tracing`, `opcache.jit_buffer_size` e.g. 64–128M). Lowest risk, immediate
   win, no API change. Verify under `composer test-load` / `tests/profile/profile.sh`.
2. **Productionize the direct fast-path** for the hot, structurally-fixed PDUs — starting
   with `SearchResultEntry` (search dominates), then evaluate `SearchRequest` filters and
   `SearchResultDone`. Wire it into the encode/decode path behind the existing interfaces so
   the generic encoder remains the fallback for everything else. This is a separate,
   reviewed branch — out of scope for this measurement spike.
3. Confirm the microbench story against a live server with the phpspy flamegraph
   (`tests/profile/profile.sh --mix=search-sub=100`) before committing to (2).

## Files in this spike

- `tests/performance/Asn1/SearchResultEntryCodec.php` — fast-path prototype (isolated).
- `tests/performance/Asn1/Asn1EncodeBenchCommand.php` — corpus + timing + correctness gate.
- `tests/bin/asn1-encode-bench.php` — CLI entry (`composer bench-asn1`).
