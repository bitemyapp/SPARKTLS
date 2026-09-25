# Linux performance results, 2026-09-24

Caching AES-GCM key preparation improved SPARKTLS TLS 1.3 bulk throughput by
about 13% for AES-128 and 14% for AES-256 on `wx-workstation`. Handshake and
ChaCha20 throughput were unchanged. All builds, tests, profiling and measurements
for this implementation ran on Linux; the Mac was used only to initiate SSH.

The original claim that SPARKTLS is faster than the C baseline needs a workload
qualifier. Before this optimization, SPARKTLS's event-loop handshake server beat
OpenSSL in this experiment, but its 16 MiB bulk transfers were slower. After the
optimization, SPARKTLS leads OpenSSL for both AES bulk suites. Rustls with AWS-LC
still leads both in AES throughput and full handshakes. This compares these server
adapters with a shared OpenSSL client, rather than languages or isolated libraries.

## Bulk transfer results

Median payload MiB/s, 20 measured samples per cell, independent server processes,
16 MiB HTTP responses over resumed TLS 1.3 connections:

| Cipher | Original SPARKTLS | Prepared-key SPARKTLS | OpenSSL | rustls / AWS-LC |
|---|---:|---:|---:|---:|
| AES-128-GCM | 3,595 | 4,058 | 3,687 | 4,582 |
| AES-256-GCM | 3,307 | 3,777 | 3,572 | 4,436 |
| ChaCha20-Poly1305 | 2,236 | 2,227 | 2,376 | 1,927 |

Within each iteration, pair the optimized and original samples, then take the
median percentage change. A paired bootstrap over those 20 iterations gives:

| Cipher | Median paired gain | 95% bootstrap interval |
|---|---:|---:|
| AES-128-GCM | +12.92% | +12.56% to +13.19% |
| AES-256-GCM | +14.48% | +13.13% to +14.94% |
| ChaCha20-Poly1305 | -0.33% | -0.66% to +0.08% |

Ratios of the throughput medians give +12.87% and +14.24% for AES. The new AES
rates exceed OpenSSL by 10.1% and 5.7%, respectively. These intervals describe
variation within this experiment, not uncertainty across CPUs or applications.
SPARKTLS's coefficients of variation were 3.7–5.1% for original AES and 3.8–3.9%
for optimized AES; process-level outliers remain in the data.

An earlier 20-sample run retained one server process per cell and appeared to
show an 8.5% ChaCha20 improvement, despite unchanged ChaCha20 instruction streams.
That gain disappeared when each sample used a fresh server process. This is
consistent with sensitivity to process layout or accumulated state; the exact
cause was not isolated. The fresh-process results above are authoritative for
bulk throughput, and fresh server processes are now the runner's default.

## Full handshakes

Median full handshakes/s, 20 measured samples per cell, one long-lived server
process per cell. These handshake results were not repeated as a 20-sample
fresh-process matrix; the final fresh-process smoke test is only an integration
check. The optimization affects application writes, not handshake cryptography.

| Cipher | Original SPARKTLS | Prepared-key SPARKTLS | OpenSSL | rustls / AWS-LC |
|---|---:|---:|---:|---:|
| AES-128-GCM | 2,485 | 2,487 | 2,309 | 3,016 |
| AES-256-GCM | 2,261 | 2,258 | 2,224 | 2,832 |
| ChaCha20-Poly1305 | 2,465 | 2,469 | 2,279 | 2,993 |

The original/new differences are below 0.2%; this change offers no demonstrated
handshake speedup.

## Implementation and correctness

`SPARKTLSCrypto.AES_GCM.Prepared_Key` retains the expanded, preswapped AES round
keys, the GHASH subkey and its four- and sixteen-block powers. The existing
AES-NI pipeline and AVX-512 kernels consume this immutable context. The software
fallback retains the original one-shot implementation. The original APIs remain
available as an independent differential oracle.

One private context is prepared lazily for each session's TLS 1.3 application
write key. It adds 611 bytes of fields, plus any containing-record padding. It
contains no nonce or counter. Existing nonce construction, counter limits,
fragmentation and capacity checks remain in place. The context is invalidated
on application-key installation and after a successfully queued local KeyUpdate;
a blocked KeyUpdate retains the old key and cache. Session/key cleanup explicitly
sanitizes all cached secret arrays. TLS 1.2 and receive-side encryption state are
not accelerated by this change.

Portable GHASH testing exposed a pre-existing branch on secret multiplier bits.
Both conditional operations in that multiplication loop now use modular byte
masks. The field arithmetic is unchanged, and the formerly failing secret-taint
test passes after the fix. This is kept separate from the cache optimization.

Validation performed:

- 8,544 prepared/one-shot/OpenSSL EVP equivalence cases per dispatch tier:
  native AVX-512, AES-NI under Valgrind, and the portable build. Cases include
  AES-128/256, every length 1–1025, TLS-sized tails, varying AAD, changing keys,
  32 buffer alignments with canaries, decrypt round trips, invalid-tag rejection
  with plaintext erasure, and complete context clearing.
- The checked CI lane repeated all 8,544 cases in accelerated and portable builds
  with runtime checks and contracts enabled. It is wired into `ci/check.sh` in
  the crypto repository. OpenSSL is a test-only oracle dependency.
- 304 TLS lifecycle checks, including both roles and key sizes, fragmented writes,
  explicit/automatic rekeying, full output buffers, cleanup and session reuse;
  passed in release and checked configurations.
- 39 unit executables exited successfully. The SHA-1 executable passed its two
  built-in vectors but skipped three external CAVP vector files that were absent.
  The vector download attempt returned HTTP 403. This is not full CAVP coverage.
- GNATprove: all checks proved for the targeted AES-GCM/GHASH units (644 reported
  checks) and targeted TLS integration units (2,167 in the final merged report).
  The four changed handshake units also passed flow analysis. This was not a
  full re-proof of every handshake theorem. No assumptions or weakened contracts
  were added. These are safety/existing-contract checks; cryptographic equivalence
  is additionally supported by the independent EVP comparisons.
- Secret-taint checks on optimized AES-NI and portable code reported zero findings;
  the negative control reported its expected finding. Valgrind's AES-NI differential
  run reported zero memory errors. AVX-512 is not covered by Valgrind on this host.
- Native timing tests used 40,000 samples per key class, randomized class order,
  fixed buffer/context addresses, and raw plus 99%-trimmed Welch statistics.
  All real tests stayed below |t| = 4.5; the deliberate timing leak exceeded it.
  This supplements the other checks; it is not a universal constant-time proof.
- The runner's 12 regression tests, Rust formatting and Clippy checks passed.
  A final fresh-process handshake/bulk smoke test passed for all four builds.
  The final rebuilt servers and rustls adapter exactly match the SHA-256 hashes
  of the measured binaries. All 153 fingerprinted production source files in
  SPARKTLS and sparktlscrypto match the fresh-process measurement snapshot.

## Conditions and reproduction

Host: AMD Ryzen Threadripper PRO 9985WX, 64 cores / 128 threads, Linux
6.17.0-1032-oem. Servers were pinned to logical CPU 32 and the client to CPU 33,
on distinct physical cores. The existing performance governor was retained;
no governor or kernel settings were changed. OpenSSL was the host's 3.0.13 build,
GNAT 16.1.0, GPRbuild 26.0.1, rustls 0.23.45 and aws-lc-rs 1.18.1.

The workload uses one sequential OpenSSL client, TLS 1.3, X25519 and an Ed25519
certificate from a fresh shared CA. Each server receives a verified preflight
outside the clock; bulk preflight checks the complete body hash and length.
Measured samples use an external monotonic clock, verify handshake/resumption
markers and exact byte counts, and rotate/reverse implementation order. Requested
`s_time` duration was one second; actual elapsed time, typically around two
seconds, is the rate denominator. One warmup precedes 20 measured samples.
See [the harness documentation](README.md) for comparison boundaries.

Both SPARKTLS builds use optimized assembly-enabled configurations with runtime
checks/contracts disabled. Correctness builds enable them separately. `gprbuild
-s` now forces recompilation after compiler-switch changes; otherwise checked or
native objects can be unintentionally reused. Dependencies and executable hashes
are retained with each result. Rustls uses the checked-in Cargo lockfile and
native AWS-LC cryptography, not a pure-Rust crypto backend.

Reproduce from the remote SPARKTLS checkout, preserving the original executables
before building the modified sources:

```sh
python3 tests/benchmarks/run.py \
  --implementations sparktls-baseline sparktls openssl rustls \
  --baseline-dir ../optimization/baseline/bin \
  --scenarios bulk --runs 20 --seconds 1 --size 16777216 \
  --restart-servers --server-cpu 32 --client-cpu 33 \
  --alr ../tools/alire/bin/alr --out ../optimization/repeat-bulk
```

Remote workspace: `/home/callen/work/sparktls-perf-2026-09-24`.
Production sources are in sibling `SPARKTLS` and `sparktlscrypto` repositories;
both changes are required. Original revisions were
`f7ea3a5eba7538e88f485f5ed252a5bd98364206` and
`b89c8bee8013498ac9008f92f4fd5480740e60df`, respectively.
The original source copies of the other dependencies are identified by source
hashes; the runner no longer mistakes an enclosing Git checkout for their repo.

Evidence under the workspace's `optimization/` directory:

- `fresh-process-20/`: authoritative bulk raw samples, fingerprints, probes and
  summaries; `fresh-process-analysis.json`: paired gains and confidence intervals.
- `comparison-20/`: long-lived-process handshake and bulk matrix.
- `baseline/bin/` and `optimized/bin/`: exact original and optimized server binaries.
- `primitive-proof-final.log`, `integration-proof-final.log`, `handshake-flow.log`:
  proof/flow results; `ci-prepared-final.log`, `checked-lifecycle.log`,
  `prepared-*-final.log`, `unit-results/`: correctness results.
- `ct-prepared-aesni.log`, `ct-prepared-portable-fixed.log`,
  `ct-negative-control.log`, `prepared-timing-test.log`: side-channel checks.
- `profiles/handshake-current-*`: refreshed CPU profile;
  `final-smoke/`: final build and integration check.

## Next aggressive optimization targets

1. **X25519 field multiplication and squaring.** The refreshed handshake profile
   attributes 57.6% of server CPU samples to X25519 scalar multiplication.
   Its current generated instruction stream contains no `mulx`. A separately
   dispatched BMI2/ADX backend is the highest-value candidate. Preserve the
   portable reference, prove limb bounds/reduction, compare full field results,
   run the protocol vectors and constant-time checks, then remeasure full
   handshakes. Do not infer a wall-clock gain directly from CPU profile shares.
   A previous global native-build experiment regressed handshakes by about 13.5%;
   target the arithmetic rather than changing every compilation unit at once.
2. **Remove redundant record copies, then reduce output copying.**
   `Write_Plaintext` builds a temporary fragment before the record builder copies
   it again. The builder already accepts nonzero array bounds. Eliminate that
   fragment copy with unchanged capacity/aliasing guarantees, then evaluate a
   borrow/consume ciphertext API with correct partial-write handling. Measure
   small records as well as bulk transfers.
3. **Profile the prepared AES-GCM path again and optimize its remaining kernels.**
   The earlier bulk profile put about 24% of samples in sixteen-block GHASH.
   Evaluate fused AES/GHASH scheduling, register pressure and smaller-record
   dispatch thresholds. Keep the existing kernels as reference implementations.
   Extend caching to receive/TLS 1.2 only after profiles justify the additional
   state, with invalid-tag, rekey and cleanup coverage for each direction.
4. **Ed25519 fixed-base multiplication.** Signing accounts for 19.1% of handshake
   CPU samples; fixed-base multiplication accounts for 15.3%. Evaluate a larger
   positional table with constant-time row selection, independently validate the
   table and preserve the scalar domain accepted by the current API. Measure its
   cache footprint alongside X25519. A previously tried X25519-via-Ed25519-basepoint
   approach was slower and should not be substituted without new evidence.

These are follow-up experiments, not implemented speedups. The committed change
removes repeated key preparation while retaining the existing record algorithms
and provides the benchmark and correctness gates for the next iteration.
