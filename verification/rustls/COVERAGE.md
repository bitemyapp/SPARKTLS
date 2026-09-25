# Coverage of the first contract tranche

The denominator is the thirteen explicitly selected contracts below, **not**
all SPARKTLS proofs, all rustls code, or all RFC MUST/SHOULD clauses. A successful
run verifies 13/13 of this selected inventory. No whole-TLS conformance score is
claimed. Consult the generated result JSON for the actual run status.

| ID | SPARK origin | Mapping | Symbolic domain |
|---|---|---|---|
| NONCE-ENC | src/sparktls-records.adb: Make_Nonce | Implementation formula (not an explicit functional SPARK postcondition) | All 96-bit IVs and all u64 sequences; unwind 14 |
| NONCE-UNIQUE | src/sparktls-records.adb: Make_Nonce | Derived strengthening: injectivity for a fixed IV | All distinct pairs of u64 sequences and all 96-bit IVs; unwind 14 |
| AAD | src/sparktls-records.adb: Build_Encrypted_Record / Hdr | Encoding formula and record-version invariant | All plaintext lengths 0..16384; fixed 16-byte tag and one inner-type byte; unwind 8 |
| U16 | src/sparktls-records.adb: TS16 | Implementation formula plus decode/encode strengthening | All u16 values; unwind 5 |
| BUFFER-TAKE | src/sparktls.ads: IO_Buffer predicate and Available | Adapted accounting invariant; rustls Reader is not the SPARK IO_Buffer | All bytes in a 0..32-byte slice, all valid initial cursors, all usize take lengths; unwind 35 |
| BUFFER-SUB | src/sparktls.ads: IO_Buffer predicate and Available | Adapted accounting/content invariant | All bytes in 0..32-byte slices and all usize sub lengths; unwind 35 |
| HEADER | src/sparktls-records.ads: Parse_Record_Header | Partial mapping: actual rustls generic policy; see discrepancies | All five header bytes (40 bits); unwind 8 |
| RECORD-FITS | src/sparktls-records.ads: Parse_Record_Header Post | Transferred fit-in-buffer postcondition, with rustls stage limits | Every available prefix of every 32-byte input; unwind 36 |
| FRAGMENT-CONFIG | src/sparktls-records.ads: Build_Handshake_Record Pre / Max_Fragment | Adapted RFC fragment-bound obligation | All Option<usize> settings and every valid prior max fragment; unwind 3 |
| FRAGMENT-BYTES | src/sparktls-records.ads: Build_Handshake_Record Pre / Max_Fragment | Adapted fragmentation safety and preservation obligation | Single-slice payloads 0..64 bytes, fragment limits 27..16384, all type/version fields; unwind 67 |
| SEQ-LIMIT | src/sparktls-records.adb: Build_Encrypted_Record counter exhaustion guard | Adapted non-wrap obligation; rustls limits are earlier | All u64 sequence numbers, additions and configured message limits; unwind 8 |
| SEQ-STEP | src/sparktls-records.ads: Build_Encrypted_Record Post | Transferred one-step counter contract, conditional on a successful provider | All write sequences below rustls hard limit; empty payload; sequence-checking provider; unwind 10 |
| KEY-RESET | src/sparktls-records.adb: Make_Nonce / Build_Encrypted_Record | Rustls lifecycle lemma needed alongside nonce uniqueness | All previous u64 read/write counters and all u64 requested limits; unwind 8 |

## Unported obligations

| Obligation | Status |
|---|---|
| SPARKTLS full strict record acceptance policy in rustls | Requires reasoning across rustls stages; generic header behavior differs |
| Record parsing above 32 bytes; fragmentation above 64 bytes | Outside bounded payload domains |
| Scatter/gather fragmentation | Not covered; only a single borrowed slice |
| Iterator ExactSizeIterator size hints | Not part of the retained fragment contract |
| Receive sequence exhaustion and key lifecycle | Unported |
| AEAD correctness/authentication, hashes, signatures and curve arithmetic | Native crypto backend outside this Rust proof configuration |
| Constant-time execution and secret erasure | Unported; Kani memory-safety checks do not establish these |
| Certificate/name verification, negotiation, full handshake transitions, key freshness | Unported |
| TLS 1.2, QUIC, async/socket concurrency and application adapters | Outside this configuration |

The first fragment harness also checked a symbolic iterator size-hint formula
and timed out after 180 seconds. The retained harness proves the relevant byte,
metadata, size and completion properties using at most three fragment steps
(ceil(64/27)); this completion bound is asserted, not assumed. It retains the
same input domain. The size-hint assertion was removed and is explicitly outside
the retained contract. All initial attempts remain in the workstation artifacts.
