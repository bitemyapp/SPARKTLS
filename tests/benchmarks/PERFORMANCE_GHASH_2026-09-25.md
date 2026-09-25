# Faster AVX-512 GHASH reduction

All work ran on wx-workstation. This continues from the Curve25519 and record
copy changes in PERFORMANCE_FOLLOWUP_2026-09-24.md. The retained production
change is the GHASH kernel; the socket-buffer experiment below was reverted.

## Retained change

The existing AVX-512 GHASH routine now uses two Montgomery folds for reduction
modulo the reflected polynomial. It combines each SIMD lane's cross terms before
the horizontal XOR and removes redundant moves. The function shrinks from 107
to 85 instructions. Its interface, H-power representation, CPU dispatch, block
ordering, counters and nonces are unchanged. No floating-point or RNG behavior
changes. The portable and AES-NI paths are unchanged.

The algebra is checked against bit-serial GHASH on all 16,384 pairs of 128-bit
operand basis vectors. Both modeled maps are bilinear over GF(2), so equality
on those pairs implies equality for all inputs. The assembler remains outside
SPARK's formal proof boundary; native tests and independent OpenSSL comparisons
check the compiled code. The argument and harness are documented in
sparktlscrypto/tests/ghash16/README.md.

Crypto commit: 227d3bf on codex/prepared-aes-gcm.

## Measurements

Twenty alternating process pairs, pinned to CPU 32, each containing twenty
warmed batch means, reduced GHASH16 time from 16.726 ns to 15.089 ns. The
median paired time reduction is 9.76%, with a within-run paired bootstrap
95% interval of 9.73–9.80%. These are batch means, not individual-call
tail latencies.

The following complete network matrix measured the retained GHASH-only build,
its preserved predecessor, OpenSSL 3.0.13, and rustls 0.23.45 with AWS-LC.
Each cell contains twenty fresh server processes and one warmup. Workload:
a 16 MiB response over resumed TLS 1.3; server CPU 32, client CPU 33.
Rates use actual monotonic elapsed time and count payload bytes only.
Higher median MiB/s is better.

| Cipher | Previous SPARKTLS | New SPARKTLS | OpenSSL | rustls / AWS-LC |
|---|---:|---:|---:|---:|
| AES-128-GCM | 4,348.66 | 4,396.52 | 3,691.97 | 4,596.56 |
| AES-256-GCM | 4,047.07 | 4,068.42 | 3,580.97 | 4,447.77 |
| ChaCha20-Poly1305 | 2,307.35 | 2,298.95 | 2,387.07 | 1,936.72 |

The paired gains are smaller than the primitive gain:

| Cipher | Median paired gain | 95% paired bootstrap interval |
|---|---:|---:|
| AES-128-GCM | +1.17% | +0.19% to +1.71% |
| AES-256-GCM | +0.27% | +0.07% to +0.96% |
| ChaCha20-Poly1305 | -0.45% | -0.81% to -0.18% |

These are within-run estimates, not promises for other workloads or hosts.
Ratios of medians differ from medians of paired ratios. All samples are
retained; the AES-256 candidate cell has a 5.90% coefficient of variation and
is marked noisy. Other cells range from 0.30% to 4.05%. The small ChaCha
regression is reported despite that cipher's unchanged implementation.

Before the change, a fresh profile attributed 30.0% of server CPU samples to
GHASH16 and 44.1% to write. Afterward, those shares were 28.6% and 44.9%.
Profiles use gperftools' generic_fp backend for flat attribution; optimized
frame-pointer stacks can be incomplete. Profiling instrumentation is never
loaded into the throughput matrix.

## Correctness and timing checks

- 20,480 native GHASH results matched independent bit-serial GHASH: every
  operand basis pair, chained states, all 64 input alignments, nonzero bounds,
  unchanged inputs and guards. The pre-change golden digest matched exactly.
  This harness and the algebra check are now included in crypto CI.
- 8,544 prepared AES-GCM cases matched OpenSSL EVP and the one-shot API with
  runtime and contract checks enabled, covering both AES key sizes, tails,
  alignment, AAD, bad tags and context erasure.
- All 564 write/key-lifecycle checks, 15 record-cap checks, 26 TLS 1.2 checks,
  and the existing VAES checks passed. A full-handshake smoke comparison passed
  for both SPARKTLS builds, OpenSSL and rustls.
- GNATprove reported all 1,666 merged safety/contract checks proved for the
  analyzed callers and specifications. This includes unchanged units and is
  not a proof of the assembler instructions.
- The instruction gate passes. The only newly allowlisted mnemonic is
  immediate-control vpshufd; it adds no CPU feature requirement.
- Three alternating baseline/candidate native timing runs passed the existing
  threshold, with 40,000 samples per key class per test. Candidate maximum
  absolute Welch t was 2.68 (threshold 4.5); its negative controls exceeded 215.
  An initial run flagged unchanged AES-256 key setup in the trimmed statistic.
  The signal did not reproduce in the controlled comparisons, and normalized
  setup disassembly was unchanged. This is evidence, not a universal
  constant-time proof.

After reverting the separate buffer experiment, every fingerprinted production
source matched the retained measurement snapshot. The rebuilt executable's
.text, .rodata, .data and .eh_frame sections exactly match the measured binary.
Its overall file hash differs because debug information changed on rebuilding.

## Benchmark build correction

A rapid source restore during diagnosis rebuilt an object but reused a stale
static archive. Disassembly caught the mismatch. Those diagnostic timings were
invalidated and retained separately. The default benchmark library build now
uses -f -s, forcing compilation and archive rebuilding; this is commit a335c6d.
All twelve existing benchmark-runner tests pass. The validation and measured
executables were checked for the new GHASH instructions.

## Socket-buffer experiment: not retained

The example server's socket staging buffer was temporarily enlarged from
16,640 to 33,280 bytes to drain the existing two-record TLS output queue in one
write. TLS record sizes, the library's buffers and short-write accounting were
unchanged. The cost was 266,240 additional BSS bytes across sixteen connections.

A slow OpenSSL receiver checked the entire 16 MiB payload under all three
ciphers, against both the prior and experimental server. A test-only accept
wrapper set a small socket send buffer to force actual backpressure. Strace
observed 16 short writes and 1,511 EAGAIN returns before, and 9 short writes
and 1,516 EAGAIN returns after. Every payload digest and TLS identity check
passed. Large write attempts fell from 4,583 to 3,055 across the three responses.
Neither the wrapper nor strace was used in performance measurements.

A five-process exploratory comparison suggested AES gains but did not establish
a ChaCha gain. Unrelated compute and compiler workloads then contaminated a
complete twenty-process comparison and another attempt after the host briefly
settled. All data is retained, but those matrices are not headline results.
The buffer change was reverted pending reliable evidence of its throughput
benefit. Only the measured GHASH optimization is retained.

## Reproduction and artifacts

Workspace: /home/callen/work/sparktls-perf-2026-09-24.

From SPARKTLS, compare the retained build with the preserved predecessor:

    python3 tests/benchmarks/run.py --scenarios bulk --implementations sparktls-baseline sparktls openssl rustls --baseline-dir ../optimization-round4/baseline/bin --runs 20 --seconds 1 --server-cpu 32 --client-cpu 33 --alr ../tools/alire/bin/alr --out ../optimization-round4/repeat

optimization-round4 contains preserved binaries, the complete network matrix,
primitive samples, algebra and golden checks, checked tests, proof report,
native timing comparisons, profiles and restored-verification.json. Invalid
stale-archive diagnostics are separated under invalid-stale-archive.

optimization-round5 contains the preserved GHASH-only server, deferred buffer
source, exploratory comparison, traced backpressure checks, memory comparison,
contaminated network measurements and host CPU-activity observations.
