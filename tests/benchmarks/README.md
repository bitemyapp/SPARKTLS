# TLS comparison benchmarks

The suite compares **SPARKTLS, OpenSSL, and rustls** with the same OpenSSL 3.x
client on the same host. It measures one client making sequential connections.
These are application benchmarks, not isolated crypto primitives or a test of
multicore server capacity.

See [the Linux measurements and optimization report](PERFORMANCE_2026-09-24.md)
for the prepared AES-GCM results. The [follow-up report](PERFORMANCE_FOLLOWUP_2026-09-24.md)
covers Curve25519 arithmetic and the record-copy experiment.

## Running

Requirements: Python 3.9+, OpenSSL 3.x, Rust/Cargo and a C compiler for rustls's
AWS-LC backend. SPARKTLS also needs Alire, the sibling dependencies installed by
`ci/fetch-deps.sh`, and a supported Ada toolchain. The SPARKTLS benchmark servers
use Linux epoll; the current crypto dependency also requires x86 instructions.
Native SPARKTLS comparisons on Apple Silicon remain unavailable. Explicitly
select OpenSSL and rustls there; the runner never silently skips an implementation.

From the repository root:

```sh
# All three implementations, all scenarios and all three cipher suites.
python3 tests/benchmarks/run.py

# Existing entry points now use the shared runner and include rustls.
tests/benchmark.sh                    # handshakes and X.509
tests/bench_bulk.sh 2 16777216         # seconds, payload bytes
tests/bench_quick.sh                  # short, exploratory correctness run

# Mac: use Homebrew OpenSSL, not Apple's LibreSSL.
tests/bench_quick.sh --implementations openssl rustls --openssl /opt/homebrew/bin/openssl

# Linux: choose two idle physical cores from lscpu (not SMT siblings).
python3 tests/benchmarks/run.py --server-cpu 32 --client-cpu 33

# A short integration check of the full matrix (not a performance claim).
python3 tests/benchmarks/run.py --runs 1 --seconds 1 --size 1048576 --x509-iters 100
```

The paths above assume the repository as the shell's current directory; the
scripts themselves resolve builds and fixtures independently of that directory.
Use `--help` for selection of scenarios, suites, repetitions and output location.
`--out` must name a new directory. By default, results go into a unique ignored
directory under `tests/benchmarks/results/`. A full default run has 20 measured
repetitions plus warmup for each cell and can take about 20 minutes.

The default rebuild forces the TLS, crypto, X.509 and ML-KEM dependencies into
their optimized configurations with contracts and runtime checks disabled. It
builds only the required example executables. Rustls uses `cargo build --release
--locked` and the checked-in lockfile. `--alr /path/to/alr` selects Alire.
`--no-build` (or `BENCH_NO_REBUILD=1`) measures existing binaries, whose build
configuration is then the caller's responsibility. `X509_ITERS` remains supported.
Build failures stop the run and retain the build log. Legacy `BENCH_CERT` and
`BENCH_KEY` overrides are replaced by fresh, common fixtures generated per run.

## Comparable work

| Scenario | SPARKTLS | OpenSSL | rustls |
|---|---|---|---|
| Full handshakes | `tls_bench_server`, epoll | `s_server` | Single worker, blocking socket |
| Resumed bulk transfers | `tls_web_epoll`, cached file | `s_server -WWW`, OS-cached file | Single worker, cached file |
| Certificate validation | `x509_validate --repeat` | `verify`, repeated leaf arguments | `WebPkiServerVerifier`, repeated leaf loads |

The handshake entry point now uses `tls_bench_server` in place of the old
`tls_blocking_server`, which allocated an Ada task per connection. Results
therefore describe the event-loop example; compare old application results
separately when investigating task creation or cleanup costs.

The rustls adapter is pinned to **rustls 0.23.45** with the **aws-lc-rs** provider.
Its cryptography includes native C/assembly; it is not a pure-Rust crypto comparison.
Exact backend versions are in [Cargo.lock](rustls/Cargo.lock). The adapter handles
one connection at a time, reuses its server configuration and ticket keys, and
uses stateless TLS 1.3 tickets. There is no thread creation per connection. See
[rustls's provider documentation](https://docs.rs/rustls/0.23.45/rustls/crypto/index.html).

All network cells use TLS 1.3, X25519 and an Ed25519 leaf issued by the same fresh
CA. The client offers exactly the selected cipher:

- `TLS_AES_128_GCM_SHA256`
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`

A verified handshake probe checks the hostname, trust, protocol, signature,
cipher and group before timing. `s_time` inherits a recorded OpenSSL configuration
that also pins X25519. Full-handshake trials require every progress marker to
denote a new connection; bulk trials require every marker to denote resumption.
The `-reuse` option alone is insufficient evidence that tickets worked.

Before bulk timing, the runner verifies the entire downloaded body against the
fixture's SHA-256 and size. Every timing result must account for the exact full
HTTP response length and total bytes. Reported MiB/s counts **payload bytes only**,
so differences in HTTP headers do not inflate throughput. The workload is one
resumed connection and one HTTP response per download, not a persistent stream.
File handling, record buffering and syscalls still differ between server adapters.

For X.509, each process retains its trust store while rereading, decoding and
validating the PEM leaf on every iteration. All check the server hostname and
server-auth purpose, with no revocation workload. A valid chain must succeed and
the same chain with an incorrect hostname must fail. Rates include process
startup and each tool's output costs, amortized across 5,000 validations by default.
They are not a comprehensive comparison of certificate-policy equivalence.

## Measurement and artifacts

Rates use externally measured monotonic elapsed time, including client startup
and teardown. OpenSSL's requested duration, rounded real-seconds summary, and
CPU-time rate are not the denominator. Its timer can run longer than requested.
OpenSSL 3.0 can return status 1 on success: the runner accepts it only with complete,
consistent counters, expected progress markers, and no reported errors.

One warmup per implementation precedes measured runs. The implementation order
rotates and reverses across trials to balance first/last position. Each summary
reports the median, range, coefficient of variation, and ratio of medians to
OpenSSL. Fewer than 20 repetitions are labeled exploratory; a coefficient of
variation above 5% is labeled noisy. These labels do not establish statistical
significance. Use a quiet host, inspect all comparator distributions, and repeat
before claiming a small win. The shared client can itself limit throughput.

Results contain:

- `status.json`: `complete` is true only after every requested cell succeeds.
- `fingerprint.json`, `build.json`, `build.log`, `binaries.json`: host, options,
  source/dependency revisions where available, effective build settings and hashes.
- `source-sha256.json`: source hashes, including uncommitted benchmark changes.
- `Cargo.lock`, `rustls-version.json`: the rustls dependency lock and adapter identity.
- Per-cell server logs, OpenSSL configuration, identity and payload probes.
- `raw.jsonl`: commands, raw client output, elapsed times, load average, counts,
  rates and warmup markers. Failed samples are retained but not summarized.
- `summary.json`: measured cells only, after the complete run succeeds.

Fixtures and private test keys live inside the private result directory; do not
reuse them outside these tests. Missing binaries, failed verification, incomplete
payloads or unsupported features fail the run. Cleanup terminates only process
groups created by this invocation. It never uses `pkill`, edits CPU governors,
or changes kernel settings. Optional Linux CPU affinity is explicit and recorded.

## Checking the harness

```sh
python3 -m unittest discover -s tests/benchmarks -p 'test_*.py'
cargo fmt --check --manifest-path tests/benchmarks/rustls/Cargo.toml
cargo clippy --locked --manifest-path tests/benchmarks/rustls/Cargo.toml -- -D warnings
```

Use the short full-matrix integration command above after changing adapters or
OpenSSL versions. On the Mac, add `--implementations openssl rustls`.

### Comparing a preserved SPARKTLS build

Use `--implementations sparktls-baseline sparktls openssl rustls
--baseline-dir /path/to/preserved/bin` to interleave the old and new servers
in the same run. Preserve `tls_bench_server`, `tls_web_epoll`, and (when
measuring certificate validation) `x509_validate` before rebuilding. The
runner fingerprints each executable, uses the same fixtures and checks for
both builds, and never rebuilds or overwrites the baseline directory.

Use `--restart-servers` to repeat the network samples in independent server
processes. Each process gets a verified handshake/payload preflight before the
clock starts. This is the default and checks sensitivity to process layout and
accumulated state; startup is not included in the rate. `--no-restart-servers`
keeps each cell's servers alive through its warmup and samples. Report which mode
you used: one long-lived server can produce a stable but unrepresentative result.

The default library build uses `-f -s` to force compilation and archive rebuilding.
This also avoids stale archives after rapid changes within the same timestamp
resolution; `-s` alone only tracks compiler-switch changes.
Source fingerprints include the sibling dependencies and generated configuration,
and are recorded after the build. Source copies inside another Git checkout are
marked as copies instead of attributing the enclosing checkout's HEAD to them.
