# Output batching and scoped sending
The first change increases the example server's staging buffer to match the
existing two-record output queue. The TLS record sizes and partial-write
accounting stay unchanged. Six slow-reader transfers (three ciphers, two builds)
passed complete payload/identity checks and exercised partial writes and EAGAIN.

Twenty fresh processes per build/cipher on wx-workstation, server CPU 32 and
client CPU 33, 16 MiB verified payloads. Paired median throughput gains:
AES-128 +3.13% (bootstrap 95% interval +2.64..+3.79), AES-256 +2.95%
(+2.30..+3.26), ChaCha20 +1.08% (+0.81..+1.24). These intervals describe
the collected pairs, not uncertainty from unrelated system activity. The
AES-128 baseline CV was 11.1%; all other CVs were below 4.3%. Concurrent user
compiler workloads remained active and were not stopped.

Raw data, build logs, binary hashes, backpressure traces and host CPU counters:
../optimization-round6/ relative to the SPARKTLS checkout. A scoped send
candidate is evaluated separately against this preserved batching executable.

## Scoped send, compared with batching alone
The example now invokes SPARKTLS.Send_Ciphertext with a synchronous socket
callback. It offers the native queued byte span, consumes only the accepted
prefix, and leaves the remainder in the session. No TLS record/counter/key/RNG
changes. Drain_Ciphertext remains available for applications needing a copy.
The example's staging buffer and duplicate output cursors are removed.
The connection pool shrinks 532,480 bytes versus batching, or 266,240 bytes
versus the original server. Disassembly confirms no memcpy/memset in Pump_Send.

Checked tests passed 8,921,332 byte/accounting comparisons plus the existing
564 write/lifecycle, 15 cap-boundary and 26 TLS 1.2 checks. A generic instantiation
with an arbitrary accepted-prefix limit proves 24 new obligations (3221 in the
merged ledger). Generic-only analysis is insufficient; the proof fixture lives
in tests/output_proof. Real slow-reader payload/identity checks passed all three
ciphers and observed nine partial writes and 1519 EAGAIN returns.

Two twenty-process matrices compared direct sending with batching. The first
used CPUs 32/33 and became heavily contaminated by other workloads. The second
selected CPUs 37/38 after observing idle physical cores and siblings, but that
run also became noisy: CVs 4.2--16.3%. Its paired throughput gains were:
AES-128 +7.11% (bootstrap 95% +2.66..+12.67), AES-256 +6.33%
(+3.81..+7.95), ChaCha20 +2.67% (-0.28..+3.32). No ChaCha throughput
gain is established. The first matrix also favored AES-128 (+7.47%).
Keep the raw noisy data; do not present these estimates as quiet-host capacity.

The native span is valid only during the callback. The caller must neither
retain it nor mutate the session through an alias. This is documented at the
API and in the proof fixture. The callback must report no more than offered;
a defensive check rejects larger counts even with assertions disabled.
