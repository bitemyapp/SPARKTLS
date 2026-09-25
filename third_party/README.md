# Vendored rustls

`rustls/` contains the published rustls **0.23.45** crate used by the comparison
adapter in `tests/benchmarks/rustls`. Its dependency is a local Cargo path, so
benchmark builds exercise this copy. The adapter lockfile retains all prior
transitive versions; only rustls's registry identity became a local path.

Upstream source: <https://github.com/rustls/rustls>, commit
`2976d90fd1c2db6b518700dd101b714069cfcb17` (package path `rustls`).
The crate archive SHA-256 is
`0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634`.
`rustls-provenance.json` records the archive URL and registry identity;
`rustls-upstream-sha256.json` records all 119 extracted upstream files.
The normalized registry Cargo.toml and Cargo.toml.orig are both retained.

The upstream Apache-2.0, ISC and MIT license files are preserved in `rustls/`.
This is the published crate, not the complete upstream repository: upstream
integration-test data omitted from the package is not present.

Local additions are three `cfg(kani)` proof modules, three corresponding module
declarations, and one Cargo lint declaration for `cfg(kani)`. Production function
bodies are unchanged. `verification/rustls/verify_vendor.py` checks every original
file after removing exactly these documented declarations. It also rejects
missing or unexplained vendor files. Ordinary Cargo build artifacts are ignored.

See [verification/rustls](../verification/rustls/README.md) for proofs, mappings,
input domains, known boundary differences, and reproduction commands. Benchmark
source fingerprints now include this directory, including local proof additions.

An upgrade requires a newly checksum-verified crate archive, refreshed provenance
and per-file hashes, review of each mapped contract, regeneration of both relevant
lockfiles, the Kani gate with controls, and native benchmark integration checks.
Do not replace the checksums simply to bypass an unexplained difference.

## SPARKTLSCrypto


`sparktlscrypto.bundle` is a self-contained Git bundle of the sibling repository,
including all twelve local optimization commits through
`7b72f82d6a77373d993fe32dbe3d97c5d94f6d8d`. This preserves both source and history in the
SPARKTLS fork; compiler binaries and benchmark build products are not included.
The bundle preserves the upstream license files as part of that history.
`sparktlscrypto-provenance.json` records its SHA-256 and upstream URL.

For a fresh checkout, run `bash ci/fetch-deps.sh`. It checks the bundle checksum,
clones it into `../sparktlscrypto`, and checks out the recorded commit. The cloned
repository's origin points to upstream for reference; the optimization commits
are not claimed to exist there. Existing sibling directories are left alone.
Setting `SPARKTLSCRYPTO_REF` explicitly retains the upstream-ref override.

To inspect or recover just the history, independently of the dependency script:

```sh
git bundle verify third_party/sparktlscrypto.bundle
git clone third_party/sparktlscrypto.bundle ../sparktlscrypto-recovered
```

If further crypto commits are made, regenerate the bundle from the sibling with
`git bundle create <absolute-bundle-path> HEAD refs/heads/codex/prepared-aes-gcm`,
then update its provenance checksum/revision and the dependency pin together.
