# First verification result

On wx-workstation, Kani 0.68.0 / CBMC 6.11.0 verified all **13 selected
harnesses**, with both negative controls detected. The complete gate took about
40 seconds with two solver jobs after setup. See [VERIFIED.json](VERIFIED.json)
for tool versions, input domains, source hashes and evidence hashes.

The unmodified production rustls files retain their upstream checksums after
removing only the three `cfg(kani)` module declarations and the lint declaration.
The benchmark now uses the vendored path. Its release build, Clippy and format
checks pass, as do all 15 benchmark-runner tests. A short integration run passes
verified full handshakes and resumed payload transfers for AES-128-GCM,
AES-256-GCM and ChaCha20-Poly1305, plus valid/incorrect-host X.509 checks.
The smoke-run rates are not a new performance comparison.

The whole-library proof is unfinished: this is the selected first tranche
listed in [COVERAGE.md](COVERAGE.md). The [boundary differences and unported
obligations](DISCREPANCIES.md) remain explicit. No native cryptography,
constant-time, secret-erasure or complete handshake proof is claimed.

Raw artifacts are on the workstation at
`/home/callen/work/sparktls-perf-2026-09-24/kani-port-artifacts/`.
`gate-third/` is the successful final gate. Earlier attempts remain alongside it:
the first fragment/size-hint formulation timed out; two early control-driver
attempts rejected Kani's generic formatted-panic diagnostic. The final nonce
harness uses Kani's explicit named assertion, which the mutation control detects.
No check or timeout was reclassified as a proof success.

The GitHub Actions job is configured to run the same gate with both controls.
Hosted CI has not been run as part of this local task.
