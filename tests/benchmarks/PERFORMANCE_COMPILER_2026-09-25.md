# GNAT array-slice miscompilation and optimization cost

All investigation, builds, tests, and measurements ran on wx-workstation.
The installed compiler, production executables, and dependency lock are unchanged.
The deliverable is an [upstream RFC packet](../compiler_vrp/README.md), including
a standalone reproducer and GCC patches. The compiler is not vendored into SPARKTLS.

## Finding

The bug is real on the installed GNAT-FSF 16.1.0 and on a separate stock GCC
16.1.0 source build. Unchecked SHA-256 is wrong at O2 and O3. GCC's memory-access
analysis applies a single-element upper-extent formula to an Ada array slice.
For eight four-byte writes beginning at offsets 0..28, it reports only 29 bytes
of possible writes instead of 32. IPA modref propagates this incorrect extent,
allowing later optimization to reuse stale values for the final three bytes.

The [44-line reproducer](../compiler_vrp/array_slice_extent.adb) requires only
GNAT. There is no SPARKTLS/SPARKNaCl dependency and no cryptographic operation.
The observed wrong SHA-256 result for `abc` ends in `e0cd19` (initial hash-state
bytes) instead of `0015ad`. The compression routine writes the correct result;
the caller's output copy is misoptimized.

The GCC patch restricts the single-element upper-extent calculation to
ARRAY_REF. ARRAY_RANGE_REF retains its conservative extent and can still use
the existing lower-offset refinement. Other VRP optimizations remain enabled.
There are no source-level algorithm, ordering, RNG, or floating-point changes.

The local tested compiler branch is `codex/ada-array-range-extent` at
`259e9cbba` in `compiler-vrp-2026-09-25/gcc`. The mainline patch preserves the
separate newer change for nonzero array lower bounds. It is apply-checked
against the exact mainline revision recorded in the packet.

## Correctness evidence

The stock and patched source builds use the same configuration and bootstrap
compiler. Both use the installed GNAT 16.1 runtime and explicitly compile the
test/application code with `-fPIE`. The experimental frontends are selected with
`-B`; no system compiler was replaced.

- The reduced test fails with stock O2/O3 and passes with stock O1, the VRP
  workaround, and patched O1/O2/O3.
- Each digest configuration checks 5,500 messages through SHA-256 and SHA-512:
  11,000 comparisons against Python hashlib. All 5,500 SHA-256 digests fail
  on unpatched O2 with VRP; SHA-512 passes.
- Patched O2, patched O3, patched checked O2, and stock guarded O2/O3 pass
  every digest. Inputs cover lengths 0..257 and 17 larger boundary lengths
  through 65,536, five array lower bounds (including 2,147,400,000), and four
  byte patterns.
- The complete upstream SPARKNaCl testall output matches its golden file with
  patched GCC, O3, and VRP enabled.
- Selected existing GCC regression checks pass at O2/O3 with both compilers.
  The scalar-array ssa-dse-35 optimization still deletes exactly one dead store.
- With the guard enabled in both compilers, the SHA-256 object's .text section
  is byte-identical. This is an additional control for the primitive comparison.

The mainline patch has not had a full mainline build. These are targeted
regression checks, not a full GCC bootstrap/testsuite run. The packet explicitly
identifies that remaining qualification required by
[GCC's contribution process](https://gcc.gnu.org/contribute.html#testing).
No upstream report or patch message has been sent.

## Software SHA-256 measurements

The author’s claim that the optimization has no noticeable cost does not hold
for this software SHA-256 workload. The guarded and fixed variants both return
correct results. No performance claim uses the incorrect VRP-enabled stock binary.

Twenty alternating fresh process pairs per message length were pinned to CPU 32,
with an extra warmup pair. Each process warms 1,000 hashes and then measures a
batch covering at least 16 MiB, with at least 1,000 calls. The next message uses
a byte from the previous digest, and final digests match across variants.
These are batch-average times per call, not individual-call tail latencies.

| Build | Message bytes | Guarded ns/hash | Fixed + VRP ns/hash | Paired throughput gain | 95% paired bootstrap interval |
|---|---:|---:|---:|---:|---:|
| O2 | 64 | 595.22 | 463.81 | +28.26% | +28.21% to +28.58% |
| O2 | 1,024 | 4,449.47 | 3,333.89 | +33.55% | +33.44% to +33.64% |
| O2 | 16,384 | 64,501.25 | 49,029.90 | +33.69% | +30.05% to +34.60% |
| O3 | 64 | 591.27 | 461.50 | +28.01% | +27.78% to +28.98% |
| O3 | 1,024 | 4,448.09 | 3,334.53 | +33.54% | +33.33% to +33.88% |
| O3 | 16,384 | 60,347.91 | 44,911.15 | +34.34% | +34.20% to +34.41% |

The intervals use 10,000 paired bootstrap resamples of process-level ratios.
CPU-time measurements agree closely with wall time. The O2 and O3 runs occurred
in separate time windows; compare variants within each row, not absolute times
across optimization levels. A 28–34% throughput increase is approximately a
22–26% reduction in time.

SPARKTLS uses a separate SPARKTLSCrypto SHA-256 implementation with SHA-NI
dispatch. The software primitive improvement therefore does not translate
directly into the same TLS improvement. SPARKNaCl's SHA-384/SHA-512 remain
relevant to the stack, which is why the application comparison includes all
three cipher suites.

## Application comparison and noise

Three isolated builds of the same current SPARKTLS/dependency sources were used:

- Current: installed GNAT, existing flags (SPARKNaCl's VRP guard already active).
- Broad guard: installed GNAT, `-fno-tree-vrp` on all compiled Ada units.
  This is a conservative experiment broader than the exact PR 18 edits.
- Fixed compiler: patched GCC 16.1, with VRP enabled for all compiled Ada units.

Each cell contains 20 measured fresh processes and one warmup. The shared
OpenSSL client checks certificate/hostname, cipher, protocol, group, full
payload hash/length, and resumption before/during the applicable trial. Bulk
uses a 16 MiB response over resumed TLS 1.3; handshakes are full TLS 1.3.
The server and client are pinned to CPUs 32 and 33, respectively. Rates use
actual external monotonic elapsed time. All 378 process trials completed.

Other workloads were active throughout. Most cells have coefficients of
variation between 7% and 13%. These medians are diagnostic results from a noisy
run and must not replace the earlier quiet SPARKTLS/OpenSSL/rustls table.

| Scenario | Cipher | Current | Broad guard | Fixed compiler | CV range |
|---|---|---:|---:|---:|---:|
| Handshake/s | AES-128-GCM | 2,388.09 | 2,363.94 | 2,370.83 | 9.37–11.87% |
| Handshake/s | AES-256-GCM | 2,187.18 | 2,219.94 | 2,253.98 | 3.80–6.03% |
| Handshake/s | ChaCha20-Poly1305 | 2,334.84 | 2,410.45 | 2,328.30 | 9.64–12.75% |
| Bulk MiB/s | AES-128-GCM | 4,271.10 | 4,182.69 | 4,222.06 | 7.70–10.61% |
| Bulk MiB/s | AES-256-GCM | 3,417.03 | 3,333.88 | 3,284.19 | 9.93–11.26% |
| Bulk MiB/s | ChaCha20-Poly1305 | 2,054.36 | 2,081.80 | 2,072.96 | 7.08–9.30% |

Paired changes relative to the current build are more useful than ratios of
separately calculated medians. Each entry shows the median paired throughput
change and its within-run 95% bootstrap interval.

| Scenario | Cipher | Broad guard vs current | Fixed vs current |
|---|---|---:|---:|
| handshake | AES-128-GCM | +0.10% [-2.09, +1.22] | +0.38% [-1.60, +1.24] |
| handshake | AES-256-GCM | +1.85% [-0.54, +4.03] | +1.97% [+0.62, +4.07] |
| handshake | ChaCha20-Poly1305 | +1.90% [-0.35, +7.75] | +0.14% [-1.36, +3.98] |
| bulk | AES-128-GCM | -0.45% [-4.49, +1.47] | +0.35% [-1.75, +1.43] |
| bulk | AES-256-GCM | -1.43% [-4.96, +5.71] | +2.35% [-8.63, +5.42] |
| bulk | ChaCha20-Poly1305 | -0.08% [-2.16, +1.91] | +1.12% [-0.82, +2.07] |

No bulk interval establishes a gain. AES-256 full handshakes show a roughly
2% paired signal with the fixed compiler, but this noisy run needs replication
before treating that as a reliable improvement. The broad-guard comparison
also does not establish zero cost: its uncertainty is too wide to bound small
changes.

## Do the earlier numbers need remeasurement?

The latest retained comparison already used SPARKNaCl 4.0.1 with
`-fno-tree-vrp`. This is recorded in
`optimization-round4/bulk-20/fingerprint.json` and corroborated by the dependency
ALI compiler switches. The manifest's `^4.0.0` constraint had resolved to 4.0.1;
it did not mean the measured binary used 4.0.0.

The production binary hashes and Alire lock still match their values before
this investigation. The bug discovery therefore does not invalidate the
[retained comparison](PERFORMANCE_GHASH_2026-09-25.md). It does not need to be
discarded or relabeled as a VRP-enabled SPARKNaCl result.

Changing the compiler or applying wider build guards changes the measured
configuration and requires new measurements. This run provides correctness
and diagnostic performance evidence, but a quiet rerun is needed for a new
official comparison table. There is no measured reason here to deploy a
private compiler merely for TLS bulk throughput. The correct course is to
retain the existing production workaround and pursue the upstream fix.

## Reproducibility

The [packet](../compiler_vrp/README.md) contains the MRE, patches, draft report,
compiler metadata, digest harness, and compact process-level evidence.
Its evidence directory includes the full paired analyses and executable hashes.
No test certificate private keys or compiler binaries are committed.

All complete build logs, optimization dumps, original client output, isolated
binaries, and scripts remain under:

`/home/callen/work/sparktls-perf-2026-09-24/compiler-vrp-2026-09-25`

Background:
[SPARKNaCl issue 37](https://github.com/rod-chapman/SPARKNaCl/issues/37),
[SPARKNaCl PR 38](https://github.com/rod-chapman/SPARKNaCl/pull/38),
[SPARKTLS PR 18](https://github.com/docandrew/SPARKTLS/pull/18).
