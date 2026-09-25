# Follow-up: Curve25519 arithmetic and record copies

All work ran on `wx-workstation`, continuing from the prepared AES-GCM change
in [the first report](PERFORMANCE_2026-09-24.md). The host, compiler, affinity and
OpenSSL/rustls configurations are unchanged. No Mac builds or tests were run.
The two candidates are measured separately so their effects can be distinguished.

## Curve25519 carry widths

`Fiat_25519.Mul` carried reduced intermediate values in 128-bit variables even
when the existing input bounds made 64 bits sufficient. Narrowing those carries
removes redundant high-word shifts and arithmetic. The 25 products and unreduced
sums still use 128 bits; reduction order and exact limb outputs are unchanged.
The public input bound, output bound and ISA requirements are unchanged. The
implementation remains SPARK; no assembly or assumed contracts were added.

Fresh profiling ranked X25519 first (40.3% of sampled server CPU) and Ed25519
signing second (30.2%). These shares differ from the previous profile, but both
identify the same shared arithmetic as a priority. Opportunity score:
impact 5 × confidence 4 / effort 2 = 10.

Twenty alternating baseline/candidate process pairs, each retaining 20 warmed
batch samples, produced these median times on CPU 32:

| Operation | Before | After | Median paired time reduction |
|---|---:|---:|---:|
| Field multiplication | 14.70 ns | 13.14 ns | 10.59% |
| Field squaring (unchanged control) | 12.33 ns | 12.34 ns | effectively unchanged |
| X25519 scalar multiplication | 22.01 µs | 20.32 µs | 7.73% |
| Ed25519 signing | 36.63 µs | 34.81 µs | 5.02% |

These are batch means, not per-operation tail latencies. The field benchmarks
use dependent chains. Generated instruction counts corroborate the reduction:
field multiply 217 → 194; X25519 scalar multiplication 2,288 → 2,186. Neither
build uses `mulx` in these functions.

The application gain is smaller. With twenty fresh server processes per cell,
TLS 1.3 / X25519 / Ed25519 / AES-128 full handshakes measured:

| Server | Median handshakes/s |
|---|---:|
| Previous SPARKTLS, prepared AES-GCM | 2,477.48 |
| SPARKTLS with narrower field carries | 2,506.03 |
| OpenSSL 3.0.13 | 2,294.36 |
| rustls 0.23.45 / AWS-LC | 3,004.29 |

The median paired SPARKTLS gain is **1.17%**, with a within-run paired bootstrap
95% interval of **0.92–1.51%**. The harness includes client and connection costs;
the primitive improvement must not be reported as an equivalent handshake gain.
This 20-sample comparison covers AES-128 handshakes, not all cipher suites or
multicore capacity. Rustls still leads this application workload.

Correctness and side-channel gates:

- 31,800 field results matched an independent OpenSSL bignum oracle modulo
  2^255-19, including full input-bound cases and 10,000 deterministic input pairs.
  An exact-limb digest captured before editing also matched. The checked CI lane
  enables runtime checks and contracts and now runs this test automatically.
- All targeted GNATprove checks passed for field arithmetic, X25519 and Ed25519
  (3,189 checks in the merged report). New assertions establish that every
  narrowed carry fits in 64 bits and the subsequent operations do not wrap.
  This preserves the original arithmetic expression, rather than substituting
  a new field algorithm. The proofs cover safety and existing contracts;
  independent arithmetic comparisons supplement them.
- Field KATs: 160/160; RFC 7748/8032 tests: 13/13; general crypto checks: 82/82.
- Production-optimized X25519 and Ed25519 secret-taint tests: zero findings;
  negative control: its expected finding. The stack-residue suite found zero
  primitive residue fragments and detected all 25 control fragments.
- Randomized native timing tests: 40,000 samples per class, fixed addresses,
  serialized timestamps, raw and 99%-trimmed Welch statistics. X25519's largest
  |t| was 1.96 and Ed25519's 1.57; both below 4.5. The control exceeded 100.
  These checks provide evidence, not a universal constant-time proof.

Crypto commit: `644e475` on `codex/prepared-aes-gcm` in `sparktlscrypto`.

## TLS 1.3 record copy experiment

The refreshed bulk profile after the arithmetic change attributed 42.7% of
samples to `write`, 28.9% to sixteen-block GHASH and 8.0% to `memcpy`. The second
candidate sends each original plaintext slice directly to the TLS 1.3 record
builder, eliminating a temporary fragment copy. TLS 1.2 retains its zero-based
buffer. Capacity checks, key updates, counters, nonce construction and record
ordering stay in the same order. No public preconditions are relaxed.

The copy removal is retained. Twenty fresh-process sample pairs per suite,
16 MiB resumed transfers, compare the preceding arithmetic build with this
single copy change. Median payload throughput is MiB/s:

| Cipher | Before | After | Median paired gain | 95% paired bootstrap interval |
|---|---:|---:|---:|---:|
| AES-128-GCM | 4,035.24 | 4,265.29 | +5.79% | +5.29% to +7.07% |
| AES-256-GCM | 3,779.13 | 3,979.86 | +5.44% | +4.25% to +5.99% |
| ChaCha20-Poly1305 | 2,231.72 | 2,288.58 | +2.98% | +1.00% to +4.09% |

Ratios of throughput medians differ slightly from median paired gains.
All samples are retained. AES process-level outliers lower individual samples
by roughly 18%; coefficients of variation range from 4.0% to 7.5%. The runner
labels cells above 5% noisy. The paired intervals remain positive, but describe
this experiment only. OpenSSL and rustls were not remeasured in this bulk matrix;
their previous rates are not mixed into the new comparison.

Validation: all 564 write/lifecycle checks pass in checked builds across both
roles and all three TLS 1.3 ciphers, including fragmented writes, best-effort
partial writes, full output buffers, unchanged caller input, rekeying and cleanup.
The record-cap tests pass 15/15 and TLS 1.2 tests 26/26. All checks for the
modified SPARKTLS unit are proved (3,197 in the merged report; this includes
previously analyzed units and is not additive with the arithmetic count).
Proof-driven restructuring puts the TLS 1.2 temporary inside its version branch,
so its initialization is explicit without adding assumptions.

The generated Write_Plaintext function shrinks from 343 to 312 instructions.
Its static memcpy call sites fall from four to two; the remaining temporary
copies belong to the TLS 1.2 paths. SPARKTLS commit: `91d50a9`.
The final handshake/bulk smoke matrix passed for SPARKTLS, its preserved
baseline, OpenSSL and rustls. The final bulk executable exactly matches the
measured SHA-256, and all 153 fingerprinted production source files match the
measurement snapshot. Final checked evidence is in
`optimization-round3/checked-*-final.log` and `proof-final.log`.

A longer post-change profiling run exposed a profiler failure: GDB caught a
SIGSEGV in libunwind while called from gperftools' SIGPROF stack walker. The
candidate then completed two sustained, roughly 26-second transfers without
profiling, as did the baseline; every response byte count and resumption marker
passed the harness checks. The normal timing matrix never loads this profiler.
Before/after sampling was repeated successfully using gperftools' `generic_fp`
backend. Optimized builds can give incomplete frame-pointer stacks, so these
profiles are used for flat hotspot attribution only. The diagnostic backtrace
and successful runs are retained under `profiles/` and `sustained-check/`.
With the same alternative sampler for both binaries, memcpy fell from 7.7% to
3.3% of CPU samples. Sixteen-block GHASH now accounts for 29.7% and write for
44.8%, including kernel time. Both profiles collected over 12,000 samples.


## Reproduction and artifacts

Workspace on `wx-workstation`:
`/home/callen/work/sparktls-perf-2026-09-24`.

`optimization-round2/` contains:

- `baseline/` and `optimized/bin/`: revisions, exact binaries and golden output.
- `primitive-processes/`: all alternating process samples and their summary.
- `handshake-20/`: full benchmark fingerprints, preflights, raw timings and summaries.
- `handshake-analysis.json`, `analyze.py`: paired gain and reproducible bootstrap.
- `proof.log`, `checked-field.log`, `test_*`, `ct_*`, `timing.log`, `residue.log`:
  correctness, proof and side-channel evidence.
- `profiles/`, `codegen.json`, `before-*.asm`, `after-*.asm`: profile and instruction evidence.

`optimization-round3/` contains the record-copy experiment's preserved baseline,
profile, checked tests, proof logs and bulk comparison. Both rounds retain failed
intermediate diagnostics separately; the final proof/test artifacts are identified
in the result discussion above.

The arithmetic harness is in `sparktlscrypto/tests/field25519/`, documented by
its README and included in the crypto CI entry point. Full handshakes use:

```sh
python3 tests/benchmarks/run.py --scenarios handshake \
  --suites TLS_AES_128_GCM_SHA256 \
  --implementations sparktls-baseline sparktls openssl rustls \
  --baseline-dir ../optimization-round2/baseline/bin \
  --runs 20 --seconds 1 --server-cpu 32 --client-cpu 33 \
  --alr ../tools/alire/bin/alr --out ../optimization-round2/repeat-handshake
```

Use the commit and preserved executables for the specific stage being reproduced;
rebuilding the final branch includes subsequent changes too. As before, verified
preflight and server startup happen outside the timed samples, actual monotonic
elapsed time is the denominator, and implementation order rotates/reverses.

## Remaining priorities

The next handshake benchmark should record server CPU per connection and add
a controlled concurrent-client workload. The smaller application gain warrants
that measurement before extrapolating primitive improvements to server capacity.

A separately dispatched BMI2/ADX field backend remains worth evaluating, with
dispatch outside the inner ladder and the current SPARK arithmetic retained as
the reference. The portable carry reduction should remain useful as that reference.

For bulk work, GHASH scheduling and the output-copy/syscall boundary now dominate
the actionable profile. A borrow/consume output API could avoid another copy, but
must preserve partial-write handling and buffer lifetimes. Kernel `write` samples
include kernel work, so they are not evidence that a single Ada routine is slow.
Ed25519 fixed-base tables remain another measured target. No gains from those
unimplemented candidates are included above.
