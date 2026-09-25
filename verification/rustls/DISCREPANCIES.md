# Contract boundary differences and known gaps

Reviewed 2026-09-25. These are differences between the two implementations or
proof scopes, not findings of exploitable TLS behavior. No production behavior
is changed to make a proof pass. No direct equivalence claim is made where a
contract cannot be transferred at the same layer.

## DISC-001: Generic record parser versus TLS 1.3 policy — ACCEPTED

SPARKTLS `Parse_Record_Header` applies type-dependent 16384/16640-byte limits,
rejects empty fragments, and normally requires record versions 0x0301..0x0304.
Its `Loose_Initial` mode relaxes the minor-version check.

Rustls `read_opaque_message_header` is a generic envelope decoder. It recognizes
content types 0x14..0x18, permits empty application-data payloads, accepts lengths
below 18432, and recognizes 0x03XX plus the other explicitly known protocol-version
enums. Protocol negotiation, content handling and later record-processing stages
carry additional checks. This first port does not verify their composition.

Affected contracts: HEADER, RECORD-FITS. The HEADER proof states the actual
rustls acceptance policy. RECORD-FITS transfers successful consumption bounds,
not SPARKTLS's stricter complete TLS 1.3 acceptance policy. An unsupported
stronger claim is listed as unported in COVERAGE.md rather than encoded as a
false expected-success harness or a silently skipped test.

## DISC-002: Cursor and buffer models — ACCEPTED

SPARKTLS has an owning fixed-capacity IO_Buffer with read/write positions.
Rustls Reader borrows an immutable slice and has one cursor. BUFFER-TAKE and
BUFFER-SUB transfer accounting, content preservation and failure atomicity
within a 32-byte domain. They do not prove SPARKTLS output allocation/borrowing,
rustls deframer compaction, or multi-buffer ownership behavior.

## DISC-003: Write limits, provider behavior and lifecycle — ACCEPTED

SPARKTLS refuses at the u64 counter boundary and increments on an emitted
record. Rustls uses earlier soft/hard limits, asks its caller to refresh/close,
and asserts refusal in `encrypt_outgoing`. Its sequence increments before the
provider returns; the provider is expected to succeed. SEQ-STEP therefore
conditions the transferred postcondition on a successful sequence-checking test
provider. SEQ-LIMIT covers refusal/no-wrap separately. KEY-RESET proves reset
and limit installation, not freshness of new key material.

## DISC-004: Cryptographic and complete protocol proofs — UNPORTED

Rustls's benchmark backend is AWS-LC, which includes C and assembly. The
SPARKTLSCrypto finite-field, AES/GHASH, signature, constant-time and erasure
proofs have no direct Rust body in this configuration to which they can be
attached. The Kani suite compiles provider-independent Rust with `std` only.
Full protocol-state, certificate, AEAD-authentication, read-counter exhaustion,
key-freshness and multi-connection concurrency properties remain outside scope.
