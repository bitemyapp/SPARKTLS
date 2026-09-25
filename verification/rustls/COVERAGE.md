# Coverage of the selected contracts

The denominator is the twenty explicitly selected contracts below, **not**
all SPARKTLS proofs, all rustls code, or all RFC MUST/SHOULD clauses. A successful
run verifies 20/20 of this selected inventory. Some entries transfer SPARK
postconditions or implementation formulas; others are explicitly labeled
rustls-specific supporting lemmas. No whole-TLS conformance score is claimed.
Consult the generated result JSON for the actual run status.

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
| RECV-STEP | src/sparktls-records.ads: Decrypt_Record Post | Transferred one-step counter and frame obligation, conditional on a successful provider and non-exhausted receive counter | All u64 read sequences below MAX, all write sequences, all prior flags/trial budgets, arbitrary 0..16-byte plaintext/type/version; unwind 19 |
| RECV-FAIL | src/sparktls-records.ads: Decrypt_Record Post | Rustls-specific failure refinement of the SPARK old..old+1 counter bound; includes trial-mode error policy | All u64 counters, Option<usize> budgets and prior decrypted flags; authentication or oversized-record error; 0..32-byte ciphertext lengths; unwind 5 |
| TRIAL-BUDGET | src/sparktls.ads: IO_Buffer accounting invariants (analogy only) | Rustls-specific trial-decryption accounting lemma; no direct SPARK 0-RTT contract | All Option<usize> budgets and all usize requested lengths, including MAX; unwind 5 |
| RECV-INACTIVE | src/sparktls-records.ads: Decrypt_Record frame/bounds (analogy only) | Rustls inactive-key lifecycle/frame lemma; SPARK decrypt has no equivalent passthrough mode | Invalid or Prepared state, all u64 counters/flags/trial budgets, arbitrary 0..16-byte payload/type/version; unwind 19 |
| READ-KEY-RESET | src/sparktls-records.adb: Make_Nonce / Decrypt_Record | Read-key lifecycle lemma needed alongside nonce uniqueness; does not prove key freshness | All previous u64 read/write counters, prior decrypted flag and Option<usize> trial budgets; all new trial budgets; unwind 8 |
| INNER-PADDING | src/sparktls-records.adb: Decrypt_Record last-nonzero scan / Plain_Len bound | Transferred last-nonzero/type and preserved-prefix formula; invalid-input signaling differs | Every byte and available prefix of an 8-byte input, all outer type/version fields; includes empty/all-zero and arbitrary padding; unwind 11 |
| INNER-LIMIT | src/sparktls-records.ads: Max_Fragment / Decrypt_Record bounds | Rustls size-policy lemma supporting bounded plaintext; not full SPARK acceptance equivalence | Lengths 0..16386 with uniform byte 0x17 (application_data), no trailing padding; unwind 5 |

## Unported obligations

| Obligation | Status |
|---|---|
| SPARKTLS full strict record acceptance policy in rustls | Requires reasoning across rustls stages; generic header behavior differs |
| Record parsing above 32 bytes; fragmentation above 64 bytes | Outside bounded payload domains |
| Scatter/gather fragmentation | Not covered; only a single borrowed slice |
| Iterator ExactSizeIterator size hints | Not part of the retained fragment contract |
| Receive sequence exhaustion at the caller; cryptographic key freshness | Unported; local success is conditional on read_seq < u64::MAX, installation/reset is covered |
| Arbitrary padded payloads above 8 bytes | Unported; a separate uniform-byte size-policy lemma covers lengths 0..16386 |
| Receive payload preservation above 16 bytes | Outside the selected domain |
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

The receive tranche initially timed out on a symbolic 32-byte padding oracle
and the merged Invalid/Prepared receive-state proof. Earlier source snapshots
and logs remain in the workstation artifacts. The retained padding domain is
0..8 bytes, with an explicit last-nonzero specification witness. The separate
length-policy lemma retains all lengths 0..16386 for uniform 0x17 bytes; its
initial arbitrary-fill/terminal-type formulation timed out and is not claimed
as proved. The inactive-state proof uses separate constant calls for Invalid
and Prepared. No timeout is counted as a proof success.
