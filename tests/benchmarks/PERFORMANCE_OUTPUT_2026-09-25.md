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
