# Direct fixed-base scans, mixed addition and fused AES-GCM

All builds, checks and measurements ran on wx-workstation. The baseline is
SPARKTLS 4747de3 with sparktlscrypto 395c9d3, the completed previous round.
No compiler flags, cipher choices, nonce rules, RNG draws, authentication checks,
or key-erasure requirements were relaxed.

## Retained changes
The fixed-base lookup selects a public row once, then scans all fifteen entries
directly. This removes 960 out-of-line point-return calls per scalar multiplication.
The generated constants and the scan live in separate units, with an explicit
loop invariant to keep proof translation bounded. The compiler uses conditional
moves from public addresses; it never indexes the table with the secret digit.

The table now stores (Y+X, Y-X, 2*d*X*Y), reduced modulo p. Substituting these
and Z=1 into the existing Edwards addition formula removes two field products
per selected addition. Point order and the zero-digit selection are unchanged.
Table storage remains 57,600 bytes. This change applies to Ed25519 signing and
the fixed-base X25519 public shares already wired into classical and hybrid TLS.
Variable-point shared-secret multiplication and its rejection checks are unchanged.

The prepared AVX-512 AES-GCM path now calls one fused sixteen-block kernel
instead of separate VAES and GHASH kernels. Ciphertext remains in zmm0--zmm3
after the required output stores, eliminating four reloads and the intermediate
vzeroupper/call boundary. Counter generation, AES rounds, GHASH products and
reduction are unchanged. The one-shot routines remain independent comparators.
Runtime feature dispatch and the AES-NI/software fallbacks are unchanged.
This is register reuse within a stripe, not a new multi-stripe scheduling algorithm.

Commits: sparktlscrypto 095e5f3 (row scan), b743d4e (mixed addition),
7b72f82 (AES-GCM fusion), and 9d93931 (timing-harness controls).

## Isolated primitive measurements
Twenty alternating process pairs per change, pinned to CPU 37, with a warmup
and twenty timed batch observations inside each process. Results below are
paired median reductions in time; intervals bootstrap the twenty process pairs.

| Change | Operation | Before | After | Time reduction, 95% interval |
|---|---|---:|---:|---:|
| Row scan | X25519 fixed base | 11.655 us | 10.318 us | 11.43% (11.36--11.61%) |
| Row scan | Ed25519 signing, 32 bytes | 16.519 us | 15.187 us | 8.09% (8.02--8.12%) |
| Mixed addition | X25519 fixed base | 10.331 us | 10.050 us | 2.71% (2.62--2.82%) |
| Mixed addition | Ed25519 signing, 32 bytes | 15.203 us | 14.882 us | 2.05% (1.96--2.19%) |

A final paired comparison against the starting build measured 11.647 to
9.010 us for fixed-base X25519 (22.64% less time) and 16.536 to 13.876 us for
signing (16.04% less time). These larger effects must not be attributed to
additional curve changes: the mixed-stage and final benchmark executables have
identical .text, .rodata and .data hashes. Execution conditions affect these
measurements. Preserve both distributions and use the application comparison
below for the combined outcome; do not multiply or add isolated stage gains.

## Prepared AES-GCM measurements
The before and after helpers use identical counts and arguments. Cached and
unchanged one-shot operations are interleaved; twenty independent process pairs
compare each key size and payload length. Times are batch means, not tail latency.

| Key bits | Bytes | Before ns | After ns | Paired time reduction, 95% interval |
|---:|---:|---:|---:|---:|
| 128 | 257 | 91.84 | 92.27 | -0.58% (-0.81% to -0.34%) |
| 128 | 1025 | 146.02 | 142.40 | 2.47% (2.25--2.82%) |
| 128 | 4097 | 376.02 | 342.46 | 8.87% (8.60--9.13%) |
| 128 | 16385 | 1294.53 | 1146.68 | 11.44% (11.07--11.51%) |
| 256 | 257 | 95.77 | 95.36 | 0.37% (0.10--0.86%) |
| 256 | 1025 | 163.96 | 154.79 | 5.58% (5.42--5.88%) |
| 256 | 4097 | 434.40 | 397.78 | 8.42% (8.09--8.55%) |
| 256 | 16385 | 1515.65 | 1368.41 | 9.72% (9.69--9.78%) |

The 257-byte AES-128 case regressed by approximately 0.4 ns (0.6%); the larger
record benefits are much greater. No new size-dependent dispatch was added
solely to tune this small difference.

## Complete TLS comparison

Twenty measured fresh server processes per implementation and cipher, plus
warmup, with rotating/reversing implementation order. The server runs on CPU 37
and the common OpenSSL client on CPU 38. TLS 1.3, X25519 and the Ed25519 chain
are pinned. Bulk uses verified resumed connections and a 16 MiB payload. Rates
use measured wall time; `s_time` is asked for one second but runs longer.
The host is a Threadripper PRO 9985WX with unrelated workloads left running.
Our builds, proofs, profilers and other benchmarks did not overlap timing.

The baseline here is remeasured in the same run; do not compare these numbers
directly with yesterday's absolute rates. Gains and confidence intervals are
medians of per-process paired ratios, so they differ from ratios of displayed
medians. Bootstrap intervals quantify these samples, not all host/frequency drift.

### full handshakes/s

| Cipher | SPARKTLS before | SPARKTLS after | OpenSSL | rustls | Paired gain, 95% interval |
|---|---:|---:|---:|---:|---:|
| AES-128-GCM | 2,690.6 | 2,731.4 | 2,299.7 | 3,007.3 | 1.51% (1.35% to 1.84%) |
| AES-256-GCM | 2,435.7 | 2,461.4 | 2,219.6 | 2,831.9 | 1.16% (0.90% to 1.51%) |
| ChaCha20-Poly1305 | 2,673.9 | 2,709.2 | 2,270.3 | 2,999.5 | 1.28% (1.19% to 1.39%) |

### payload MiB/s

| Cipher | SPARKTLS before | SPARKTLS after | OpenSSL | rustls | Paired gain, 95% interval |
|---|---:|---:|---:|---:|---:|
| AES-128-GCM | 4,752.8 | 5,074.8 | 3,678.1 | 4,546.9 | 6.53% (6.32% to 7.19%) |
| AES-256-GCM | 4,398.6 | 4,660.7 | 3,609.1 | 4,411.3 | 6.28% (5.62% to 7.37%) |
| ChaCha20-Poly1305 | 2,415.2 | 2,413.0 | 2,379.4 | 1,923.6 | -0.03% (-0.35% to 0.11%) |

### Server CPU per full handshake

| Cipher | Before us | After us | Paired CPU reduction, 95% interval |
|---|---:|---:|---:|
| AES-128-GCM | 83.30 | 76.97 | 6.47% (5.86% to 7.74%) |
| AES-256-GCM | 117.12 | 111.70 | 4.91% (4.37% to 5.69%) |
| ChaCha20-Poly1305 | 82.34 | 77.34 | 6.37% (5.76% to 7.68%) |

CPU accounting brackets the client command and excludes server startup and
preflight; it has Linux clock-tick resolution. The sequential-client rates do
not measure server capacity.

### Variation and controls

| Scenario / cipher | Before CV | After CV | OpenSSL CV | rustls CV |
|---|---:|---:|---:|---:|
| handshake / AES-128-GCM | 0.32% | 0.30% | 0.60% | 2.66% |
| handshake / AES-256-GCM | 2.99% | 1.49% | 0.69% | 0.94% |
| handshake / ChaCha20-Poly1305 | 0.34% | 0.40% | 0.48% | 0.46% |
| bulk / AES-128-GCM | 3.96% | 0.55% | 0.58% | 0.47% |
| bulk / AES-256-GCM | 5.38% | 0.64% | 0.44% | 1.07% |
| bulk / ChaCha20-Poly1305 | 0.29% | 1.91% | 0.28% | 0.63% |

**The AES-256 bulk baseline is noisy** under the suite's greater-than-5% CV
rule (5.38%). Its paired interval remains positive, but the extra variation
limits precision. No observations were discarded. ChaCha bulk throughput has
no clear change; its interval crosses zero. Its server CPU/response increased
by 0.20% in this run, with a paired interval of 0.04% to 0.33%.

Versions: OpenSSL 3.0.13; rustls 0.23.45 using aws-lc-rs 1.18.1 / aws-lc-sys 0.45.0.
These comparisons include the different example servers, record buffering and
syscalls; they are not a general ranking of every workload or crypto backend.

## Saturated handshake capacity

Eight OpenSSL clients, pinned to CPUs 38 through 45, issue new AES-128-GCM
handshakes against one server pinned to CPU 37. Each client verifies the shared
CA, and a verified hostname/cipher/group preflight precedes every server trial.
Twenty alternating fresh-process pairs follow a separate warmup. Rates divide
total completed connections by the shared measured wall interval, including
client startup and teardown. This is a same-server before/after capacity test;
OpenSSL and rustls were not tested in this concurrency configuration.

| Metric | Before | After |
|---|---:|---:|
| Full handshakes/s, median | 11,626.21 | 12,391.15 |
| Server CPU utilization, median | 99.80% | 99.79% |
| Server CPU us/connection, median | 85.75 | 80.53 |
| Throughput coefficient of variation | 0.55% | 0.23% |

The paired capacity gain is **6.68%**, with a 95% bootstrap interval of
**6.29% to 6.90%**. Paired server CPU/connection falls **5.99%**
(5.89% to 6.39%). The independent three-pair pilot also saturated the core;
its exploratory observations are retained separately and excluded above.

## Validation
- All 4,096 complete curve oracle cases retain the previous serialized golden
  SHA-256 326c6c2d973319ef61996edb804afe865190cfd13af7ef393bf3c5c4488fd764.
  The checked optimized oracle and native signing/X25519 taint checks pass.
- Scoped Ed25519/table/scan proofs pass, including the new mixed-addition bounds.
  These preserve the existing bounds/runtime-safety proof model; they are not
  a complete mathematical group-law proof. No assumptions or SPARK-Off bodies
  were added to the curve changes.
- Stack-residue checks find zero secret fragments and detect all 25 controls.
- 8,544 complete prepared-AEAD comparisons pass against OpenSSL and the one-shot
  implementations under checked hardware and portable configurations.
- 8,192 direct fused/unfused kernel comparisons cover both key sizes, all 64-byte
  alignments, nonzero array bounds, arbitrary counters and incoming GHASH states,
  and buffer/accumulator guards. The reference digest is 8091673054100983235.
- The changed Encrypt_Prepared caller passes its scoped proof. New assembly
  composes the existing instructions; no arithmetic formula or feature test
  changes. Native instruction inspection passes the existing allowlists.
- Native AES-GCM key-class timing passes 40,000 observations/class; maximum
  absolute Welch statistic is 2.09, against a 4.5 threshold. The negative
  control is detected. Valgrind does not execute AVX-512 here, so no claim of
  AVX-512 taint coverage is made.
- Verified in-memory classical and hybrid TLS handshakes and encrypted echo pass.

## Curve timing investigation
The initial native 40,000/class run flagged fixed-base X25519 (trimmed t=-7.89).
All outputs are retained. Three matched follow-up process pairs produced no
candidate flags, but the unchanged baseline flagged its unchanged variable-point
ladder once (trimmed t=-4.84). This suggests measurement instability; it does not
establish its cause.

The helper now accepts observation count, class-order seed and operation name.
The original crypto source and candidate were rebuilt with that identical helper
and production settings. Three independent seeds each collected 200,000 samples
per class from fixed-base X25519, plus the negative control. All six runs passed:
maximum absolute t was 2.135 for the baseline and 1.430 for the candidate.
The native taint checks and instruction/address review remain separate evidence.
No threshold was loosened. A diagnostic local-volatile mask change was rejected
by SPARK and reverted before native execution; no mask barrier was retained.

## Rejected field-arithmetic experiment
An isolated 5x51-bit BMI2/ADX prototype passes 31,800 OpenSSL arithmetic checks
and the exact-limb baseline digest. In twenty process runs allowing the old
functions to inline, it took 13.13 ns versus 8.45 ns for multiplication, and
9.64 ns versus 7.23 ns for squaring. These figures are specific to that benchmark,
not directly comparable to the separate out-of-line field helper. They exclude
feature-dispatch overhead. The prototype is retained as an experiment and adds
no production field backend.

The full-ladder follow-up passed 4,096 differential cases per process. Ten
exploratory processes measured 20.24 us for the unchanged X25519 implementation,
26.07 us with prototype multiplication (28.76% slower), and 31.26 us with
prototype multiplication and squaring (54.44% slower). The final inversion
remains the original implementation in all variants. This reinforces rejecting
this particular prototype; it does not rule out a better scheduled ADX backend.

## Final profile and remaining work

Separate 25-second gperftools profiles sample the existing optimized binaries
at 500 Hz after startup. They use the generic frame-pointer unwinder; optimized
frame omission limits caller attribution. Profile timings are diagnostic and
excluded from all performance tables.

The AES-128 bulk profile collected 12,386 samples: 48.2% are attributed to the
write wrapper, 33.8% to the fused AES/GHASH kernel, 7.3% to record building and
2.2% to counter construction. The write bucket includes time observed at the
syscall boundary and must not be read as pure userspace call overhead.
Further bulk gains need either reduced socket/kernel work or a better scheduled
multi-stripe crypto kernel; the eliminated ciphertext reloads are already gone.

The full-handshake profile collected 2,554 samples: 22.1% in the variable-point
X25519 ladder, 10.6% in fixed-base mixed addition, 7.6% in field inversion,
5.8% in SHA-256 compression, 5.6% in table selection and 5.1% in Ed25519 scalar
reduction. Future curve work should test scheduling/register pressure inside the
whole ladder, or a proved inversion/reduction improvement. Merely replacing
individual products with the ADX prototype does not help this build.

## Artifacts and reproduction

Everything is retained on `wx-workstation` beneath
`/home/callen/work/sparktls-perf-2026-09-24/optimization-round7/`:

- `baseline/identity.json` and `baseline/bin/`: starting commits and binaries.
- `lookup-final-processes/`, `mixed-processes/`, `final-curve-processes/`:
  independent process observations for the curve changes.
- `curve-binary-section-comparison.json`: identical mixed/final machine-code
  sections despite different absolute primitive timings.
- `fused-processes/`: prepared and one-shot AEAD measurements.
- `final-20/`, `final-analysis.json`, `final-20-activity.json`: complete application
  matrix, raw trials, binaries, source hashes, host settings and CPU activity.
- `concurrent-8-20/`: saturated capacity comparison; `concurrent-8-3/` is the
  separate exploratory pilot.
- `lookup-final-validation.json`, `mixed-validation.json`, `mixed-checked.log`,
  `mixed-residue.log`, `final-curves-proof.log`: curve checks and scoped proof.
- `curve-timing.log`, `curve-timing-diagnosis.json`, `timing-extended.json`,
  `timing-disposition.md`: original timing flags and every investigation result.
- `fused-direct.log`, `fused-checked.log`, `prepared-checked-enabled.log`,
  `prepared-checked-disabled.log`, `fused-proof.log`, `fused-timing.log`,
  `mnemonics.log`, `integration-native.log`: AEAD and TLS validation.
- `field-prototype/`: rejected ADX source, primitive and full-ladder measurements.
- `profiles/`: final raw and symbolized profiles.
- `final-verification.json`: final revisions, binary/source matches and evidence
  hashes. Proof summaries can contain merged prior-unit results; do not sum their
  counts or claim a fresh whole-project/full group-law proof.

The artifact directory also contains the build, proof and measurement drivers.
To repeat the application comparison using the preserved binaries, choose a new
output directory and run on the workstation:

```sh
cd /home/callen/work/sparktls-perf-2026-09-24/SPARKTLS
python3 tests/benchmarks/run.py --no-build \
  --scenarios handshake bulk \
  --implementations sparktls-baseline sparktls openssl rustls \
  --baseline-dir ../optimization-round7/baseline/bin \
  --runs 20 --seconds 1 --server-cpu 37 --client-cpu 38 \
  --out ../optimization-round7/repeat-20
```

Baseline source: SPARKTLS `4747de3590f7593718d0ea0f3d15cd584bc736f3`,
crypto `395c9d3131f111c0d72979b697bf418493270ba8`.
Final measured code: the same SPARKTLS source with crypto
`7b72f82d6a77373d993fe32dbe3d97c5d94f6d8d`.
This report and its README link are documentation-only changes afterward.
