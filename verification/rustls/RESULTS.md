# Verification results

On wx-workstation, Kani 0.68.0 / CBMC 6.11.0 verified **20/20 selected harnesses**
and detected all **four negative controls**. The complete gate took 185.5
seconds with two solver jobs. Input hashes were unchanged throughout the run.
[VERIFIED.json](VERIFIED.json) records tool versions, domains and source hashes;
[the evidence directory](evidence/2026-09-25-receive/) preserves compressed raw
Kani exports, logs, checksums and the complete run summary in Git.

This tranche adds seven contracts: successful receive sequencing and plaintext
preservation; failed receive/trial-error handling; trial-budget accounting;
inactive-key passthrough; read-key installation; TLS 1.3 padding/type recovery;
and the inner-plaintext size policy. The existing thirteen contracts also pass.
The new mutation controls detect a removed receive-counter increment and a
forced application_data inner type. The nonce mutation and insufficient-unwind
controls remain in place. Mutants exist only in isolated verification copies.

Successful receive is conditional on a non-exhausted counter; the caller-level
exhaustion guarantee remains unported. Arbitrary-byte padding coverage is
0..8 bytes. The separate size-policy lemma covers every length through 16386
using uniform 0x17 bytes without trailing padding. It does not establish
arbitrary large-record correctness. Read/receive/fragmentation domains and all
remaining gaps are listed in [COVERAGE.md](COVERAGE.md) and
[DISCREPANCIES.md](DISCREPANCIES.md).

All 119 upstream files still match their original checksums after removing only
the permitted proof declarations/lint. Normal production Rust code is unchanged.
The native benchmark adapter passes `cargo check --locked`, all 15 benchmark
runner tests pass, and the proof sources pass rustfmt. The earlier release,
Clippy, full/resumed TLS and X.509 smoke validation at commit `0696833` remains
historical evidence; those integration runs were not repeated for this proof-only
change. No new performance comparison is claimed.

Earlier attempts are retained under
`/home/callen/work/sparktls-perf-2026-09-24/kani-port-artifacts/`.
`receive-first/`, `receive-second/` and `receive-third/` record solver timeouts
and intermediate formulations; `receive-focused/` records the successful
reformulations; `receive-final/` is the complete passing gate. The initial
32-byte padding domain was reduced explicitly. Separate constant calls for the
inactive states recovered the original 16-byte domain without restricting its
inputs. No timeout or incomplete run is counted as a successful proof.

The GitHub Actions job runs the same gate with all four controls. Hosted CI has
not been run as part of this task. Native cryptography, constant-time behavior,
secret erasure and complete TLS/handshake correctness remain outside this port.
