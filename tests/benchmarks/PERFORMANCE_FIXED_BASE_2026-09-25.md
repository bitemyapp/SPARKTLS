# Fixed-base curve multiplication
The new Scalarbase uses [k * 256**i]B tables for all 32 byte positions. It
accumulates high nibbles, doubles four times, then accumulates low nibbles:
S = sum_i (16*hi_i + lo_i)*256**i. The result represents exactly [S]B.
There are still 64 selected point additions, but only four doublings rather
than 256. The public affine table stores X, Y and T; Z=1 is implicit.
Its 57,600 data bytes replace the previous 2,400-byte table (+55,200 bytes).
All fifteen entries are scanned at each public position. No new assembly,
SPARK-Off body, secret-dependent index, RNG draw or weakened contract is added.

## Primitive measurements
On wx-workstation, CPU 37: twenty alternating before/after process pairs,
twenty warmed batch samples per operation per process. The baseline uses the
corrected 96-byte signed-message helper, crypto revision 1e1cda5.

| Operation | Before | After | Paired reduction in time (bootstrap 95% interval) |
|---|---:|---:|---:|
| X25519 fixed-base API | 29.886 us | 11.682 us | 60.92% (60.89--61.35%) |
| Ed25519 signing, 32-byte message | 34.807 us | 16.555 us | 52.46% (52.38--52.71%) |
| X25519 arbitrary-point multiplication | 20.281 us | 20.261 us | 0.06% (-0.03--1.13%) |
| Field multiplication | 13.152 ns | 13.151 ns | 0.006% (-0.04--1.37%) |
| Field squaring | 12.282 ns | 12.274 ns | 0.03% (-0.01--1.17%) |

TLS previously generated its public shares with the general Montgomery ladder,
not the older fixed-base API. Both client and server now call the faster
fixed-base path for classical and hybrid public shares. The peer shared-secret
calculation still uses the general ladder, with the same rejection checks.
For this TLS call-site change, the primitive comparison is 20.281 us to
11.682 us, about 42% less time. The 61% figure above compares the two fixed-base
implementations and must not be attributed directly to TLS key generation.

Unchanged operations serve as controls. These are batch means, not tail
latencies, and do not imply the same gain in TLS throughput.

## Correctness and native-code checks
- All 480 public points regenerate with independent Python integer arithmetic,
  including a curve-equation check for each point.
- 4,096 deterministic cases match OpenSSL's Ed25519 public keys/signatures and
  X25519 public keys, the existing Montgomery ladder and Sign/Open round trips.
  All serialized outputs match the pre-change SHA-256 golden
  326c6c2d973319ef61996edb804afe865190cfd13af7ef393bf3c5c4488fd764.
- Checked optimized arithmetic passed the new oracle and the existing 82 crypto,
  13 RFC and 160 field KAT checks. The final row representation also passes the
  native optimized oracle and golden.
- GNATprove discharged all targeted Ed25519/table obligations; the merged
  ledger contains 3192 proved checks. These establish bounds and runtime safety,
  not the complete group-law equivalence; the algebra and independent oracle
  supplement the existing proof model.
- Native production settings: zero secret-taint findings in Ed25519 signing
  and both X25519 paths. The deliberately leaky control produced its expected
  tainted-memory-access finding.
- Native key-class timing: 40,000 observations/class, same input/output
  addresses, randomized class order. Maximum |t| across raw/99%-trimmed results:
  X25519 ladder 1.24, X25519 base 1.47, Ed25519 signing 1.10. Threshold 4.5;
  control |t| >=118. Statistical checks are supporting evidence.
- Stack residue: zero secret fragments; all 25 control fragments detected.

## Application measurements
The client/server integration additionally passes actual in-memory TLS 1.3
handshakes and bidirectional encrypted messages, with certificate, hostname and
UTC validity checks enabled, for forced X25519 and forced X25519MLKEM768.
Both checked and production-library configurations pass. PSK wiring passes
24 checks and entropy-failure handling passes 13. All three changed
key-generation helpers pass scoped proof runs (3236 checks in the merged ledger).

The first network run, final-20, was stopped when inspection showed that TLS
still used the general ladder for its public shares. That incomplete run is
retained as intermediate evidence only. The integrated-20 matrix measures the
complete implementation against the starting binaries and both comparators.
The completed matrix uses twenty fresh server processes per implementation/cell,
one warmup, rotated/reversed implementation order, server CPU 37 and client CPU 38.
Each timed command requests one second; rates use its actual measured wall time.
TLS 1.3 uses X25519 and the same Ed25519 certificate. Bulk transfers verify a
16 MiB payload. OpenSSL is 3.0.13; rustls is 0.23.45 with AWS-LC 1.18.1.
These results compare the complete output and curve changes with the starting
production binaries, not fixed-base multiplication alone.


| Workload | Cipher | Starting SPARKTLS | Final SPARKTLS | OpenSSL | rustls |
|---|---|---:|---:|---:|---:|
| handshakes/s | AES-128-GCM | 2,505.6 | 2,687.3 | 2,291.9 | 2,999.7 |
| handshakes/s | AES-256-GCM | 2,265.9 | 2,417.4 | 2,195.4 | 2,809.4 |
| handshakes/s | ChaCha20-Poly1305 | 2,369.7 | 2,624.5 | 2,181.5 | 2,844.6 |
| MiB/s | AES-128-GCM | 4,062.4 | 4,443.9 | 3,473.1 | 4,389.3 |
| MiB/s | AES-256-GCM | 4,033.1 | 4,361.5 | 3,567.4 | 4,412.1 |
| MiB/s | ChaCha20-Poly1305 | 2,293.1 | 2,405.7 | 2,355.1 | 1,927.9 |

The table contains medians. The following effects are medians of paired ratios,
which need not equal ratios of the displayed medians. Intervals bootstrap the
twenty process pairs (20,000 resamples, seed 25519); they do not capture all
uncertainty from unrelated host activity.

| Workload | Cipher | Paired throughput gain (95% interval) | Paired server CPU reduction (95% interval) | Rate CV range, all four builds |
|---|---|---:|---:|---:|
| handshake | AES-128-GCM | 7.35% (6.94--7.61%) | 24.11% (23.49--25.50%) | 2.0--4.0% |
| handshake | AES-256-GCM | 6.47% (5.88--6.77%) | 18.06% (17.33--18.39%) | 1.1--2.9% |
| handshake | ChaCha20-Poly1305 | 7.64% (6.84--10.46%) | 24.51% (24.30--26.06%) | 14.4--21.4% |
| bulk | AES-128-GCM | 10.60% (9.26--19.70%) | 9.68% (8.77--16.36%) | 13.3--15.8% |
| bulk | AES-256-GCM | 8.29% (7.06--9.39%) | 8.32% (7.04--9.20%) | 1.4--9.9% |
| bulk | ChaCha20-Poly1305 | 4.65% (4.29--5.13%) | 4.57% (3.86--5.21%) | 4.7--8.1% |

Server CPU comes from Linux user+system counters around the timed command,
excluding startup/preflight and child processes. Handshake CPU is per completed
handshake; bulk CPU is per completed 16 MiB response. Clock-tick quantization
makes these averages, not individual request timings.

| Cipher | Starting handshake CPU | Final handshake CPU | OpenSSL | rustls |
|---|---:|---:|---:|---:|
| AES-128-GCM | 109.52 us | 82.96 us | 173.65 us | 46.70 us |
| AES-256-GCM | 144.56 us | 118.36 us | 186.03 us | 60.02 us |
| ChaCha20-Poly1305 | 111.71 us | 83.34 us | 180.71 us | 47.69 us |

Other workstation jobs remained active. ChaCha handshakes and all bulk cells
include noisy distributions, so the comparator medians are observations on this
host, not universal rankings. In particular, the approximately 1% AES throughput
difference between SPARKTLS and rustls is not an established win for either.
The repeatable primitive and handshake CPU reductions provide stronger evidence
for the fixed-base change than the single-client wall-rate difference alone.

## Four-client handshake check
A separate AES-128-GCM/X25519 comparison pins one server to CPU 37 and four
OpenSSL clients to CPUs 38--41. Twenty alternating fresh-process pairs plus
one warmup per build use the same verified identity and group. Counts from all
four clients share one wall-clock interval, from the first launch through final
completion. Source binaries match the main matrix; raw per-client outputs are
retained in concurrent-20.

| Metric | Starting SPARKTLS | Final SPARKTLS |
|---|---:|---:|
| Median full handshakes/s | 9,074.5 | 10,152.1 |
| Rate CV | 0.28% | 0.82% |
| Median fraction of one server CPU | 99.57% | 85.90% |
| Median server CPU per handshake | 109.69 us | 84.53 us |

The paired throughput gain is 11.92% (95% bootstrap interval 11.59--12.40%);
paired server CPU falls 22.97%. The final server is not fully CPU saturated, so
this measures four-client throughput, not its maximum handshake capacity.
No unrelated processes were stopped or reprioritized.

## Final profile and remaining work
Post-change profiles use the production binaries, gperftools' generic frame
pointer unwinder and 500 Hz CPU sampling. Profile runs are separate from all
headline timing measurements. Flat symbols locate work; percentages are not
before/after absolute-time measurements and can rise when other work shrinks.

The AES-128 handshake profile collected 2,877 samples. The remaining variable-
point X25519 ladder accounts for 21.8%; Edwards point additions 11.8%, SHA-256
6.7%, field inversion 6.6%, public table access 4.8% and modular scalar reduction
4.1%. Point doubling is down to 0.5% of samples. The ladder and field operations
are the next curve targets; changing the public table lookup must continue to
scan every entry independently of the secret digit.

The bulk profile collected 12,296 samples: 45.7% attributed to write, 29.5% to
16-block GHASH, 7.4% to record construction, and 5.4% to VAES encryption.
memcpy accounts for 0.1%. Fusing AES/GHASH and further reducing socket work are
still candidates, not changes included in this report.

Implementation commits: SPARKTLS e527bb1 (batching), 7d28584 (scoped send),
c7f2f8e (public-share integration); sparktlscrypto 7472e0d (fixed-base table).
Benchmark/helper corrections: SPARKTLS 8c8ad3c and sparktlscrypto 1e1cda5.
Follow-up documentation/test housekeeping: SPARKTLS 894b131 and
sparktlscrypto 395c9d3. Compilation and verification ran only on wx-workstation.

Artifacts: ../optimization-round6/ relative to the SPARKTLS checkout. Preserved
binaries, paired primitive CSVs, proof logs, timing/taint/residue results, golden
outputs, source hashes and full network samples are retained there.
The authoritative matrix is integrated-20; final-analysis.json contains the
paired analysis and per-implementation CVs.
