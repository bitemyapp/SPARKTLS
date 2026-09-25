# SPARK contract transfer to rustls with Kani

This is a selective port of SPARKTLS record-layer obligations to the
vendored rustls 0.23.45 implementation. Twenty harnesses call the actual Rust
code and verify symbolic inputs. They are compiled only under `cfg(kani)`;
normal benchmark builds use the same upstream production code.

There is no automatic translation of GNATprove results to Kani. Some harnesses
transfer explicit postconditions, some adapt buffer or record-size invariants,
and others strengthen short SPARK implementation formulas. Each mapping is
identified in [COVERAGE.md](COVERAGE.md) and [contracts.json](contracts.json).
The SPARK reference revision and file hashes are in
[spark-reference.json](spark-reference.json).

The scope includes nonce encoding/uniqueness, TLS 1.3 additional-data headers,
u16 encoding, reader accounting, bounded record parsing and fragmentation,
write-sequence exhaustion, receive-side bookkeeping, trial-decryption budgets,
key installation, and TLS 1.3 padding removal. It does **not** establish
whole-library or full TLS conformance. In particular, it does not port the
SPARK arithmetic proofs to AWS-LC, or prove authentication, the full handshake
state machine, certificate validation, constant-time execution or key erasure.

The [verification results](RESULTS.md) record the Linux run and its evidence.

## Run on x86-64 Linux

Install the pinned verifier using the [official Kani installation procedure](https://model-checking.github.io/kani/install-guide.html):

```sh
cargo install --locked kani-verifier --version "$(cat verification/rustls/KANI_VERSION)"
cargo kani setup
bash ci/rustls_kani.sh --self-test
```

Kani 0.68.0 supplies its own Rust compiler and CBMC. These harnesses use the real
crate with `--no-default-features --features std --lib`, so neither the native
AWS-LC/ring backends nor TLS 1.2 are compiled into the proof configuration. The
normal benchmark retains its `std,aws_lc_rs` configuration and locked dependencies.
The independent published rustls lockfile is used for the proof configuration;
it is not the benchmark's lockfile. Both are tracked and checksummed.

On the workstation used for this port, the isolated installation can be selected
without changing the default Rust toolchain:

```sh
cd /home/callen/work/sparktls-perf-2026-09-24/SPARKTLS
KANI_HOME=/home/callen/work/sparktls-perf-2026-09-24/tools/kani/home \
  bash ci/rustls_kani.sh \
  --cargo-kani /home/callen/work/sparktls-perf-2026-09-24/tools/kani/bin/cargo-kani \
  --self-test
```

`--out` selects a **new** result directory; otherwise each run gets a fresh
ignored directory under `verification/rustls/results/`. `--jobs 1` reduces solver
concurrency; the default is two. Each harness has a 180-second timeout, and the
whole invocation has a twenty-minute timeout. The driver terminates only its
own process group on timeout.

The driver verifies the vendor checksums, pinned Kani version and exact harness
inventory. A missing harness, solver error, timeout, failed check, or dependency
lockfile change fails the run. Kani's JSON output includes individual properties
and tool versions. `summary.json` records the input domains and source hashes;
`status.json` is marked complete only after every required check succeeds.
Kani does not expose `--locked`; Cargo metadata is checked with `--locked` first,
and the driver rejects any lockfile change during proofs or controls. It also
hashes all proof inputs before and after the run and rejects concurrent changes.

With `--self-test`, four failures are required and checked separately:

1. In an isolated copy, change rustls's nonce prefix initialization. The unchanged
   nonce-contract harness must fail its named functional assertion.
2. In another isolated copy, remove the receive-counter increment. The unchanged
   successful-receive harness must fail its named counter assertion.
3. In another isolated copy, force the extracted inner content type to
   application_data. The unchanged padding harness must fail its type assertion.
4. On the original implementation, force a one-iteration unwind limit. Kani must
   report an unwinding assertion failure, demonstrating that insufficient loop
   exploration is not silently accepted.

None of the controls changes the working production source. They are not
counted as verified properties. The CI job runs all four controls and uploads its raw results.

## Meaning of a successful run

Kani exhaustively checks the symbolic domain stated for each harness, including
its automatic safety checks. It does not infer a guarantee beyond that domain.
Reader proofs use up to 32 bytes; arbitrary-padding proofs use up to 8 bytes;
receive passthrough proofs use up to 16 bytes; fragmentation uses up to 64 bytes in a single slice.
The size-policy proof separately covers lengths 0..16386 using uniform 0x17
bytes without trailing padding. Nonce arguments and trial budgets use full
integer widths. Successful receive requires a sequence below u64::MAX; failed
and inactive receive cover all u64 values.
[Loop bounds and unwinding assertions](https://model-checking.github.io/kani/tutorial-loop-unwinding.html)
remain enabled. There are no function stubs, `should_panic` harnesses, disabled
assertion checks, or ignored assembly in the positive suite.

The outgoing-record proof installs a sequence-checking test provider which
succeeds on an empty payload. This proves rustls's sequence handoff and update
around a successful provider call, not the provider's encryption. The write
policy proof independently covers all counter values and configured limits.
Receive proofs use a sequence-checking provider with success/authentication/other
error outcomes. They establish counter, flag and budget transitions around
those outcomes, not AEAD correctness. Read-key installation is covered; the
caller/lifecycle guarantee against exhausting the receive counter remains open.

The generic header parser is deliberately tested against rustls's policy.
SPARKTLS's stricter version/type/length checks cannot simply be asserted at that
same function boundary. [DISCREPANCIES.md](DISCREPANCIES.md) records these differences
and the obligations still needed at higher layers.

The published rustls crate omits upstream integration-test data. We preserve that
published package rather than claim to have run rustls's full upstream suite.
Native validation builds the benchmark against the vendored path, runs its
Clippy/format checks, and exercises verified handshakes, resumed payloads and
certificate validation through the existing comparison runner.
