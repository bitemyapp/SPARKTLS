# Receive-contract verification evidence

The five compressed JSON files are the unmodified Kani exports from the positive
suite and four negative controls. They are compressed only to keep the repository
small. `MANIFEST.json` records both compressed and uncompressed SHA-256 values;
`SHA256SUMS` covers the exported evidence files (excluding this README).

```sh
sha256sum -c SHA256SUMS
gzip -dc kani.json.gz > /tmp/rustls-kani-receive.json
```

`summary.json` records exact input hashes, tools, command and domains.
`status.json` counts only the twenty positive contracts as verified. The three
mutants and low-unwind control are required failures, not additional proofs.
The raw logs and native adapter/runner checks are retained alongside them.
Absolute workstation paths identify the original invocation; rerun using the
repository's `ci/rustls_kani.sh --self-test` command.
