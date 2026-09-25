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
Full protocol-state, certificate, AEAD-authentication, caller-level read-counter
exhaustion, key-freshness and multi-connection concurrency properties remain
outside scope.

## DISC-005: Receive counters and trial decryption — PARTIAL

SPARKTLS `Decrypt_Record` checks exhaustion locally and advances its counter
before calling the AEAD provider, including when authentication later fails.
Its postcondition permits an unchanged counter or one increment, with a separate
fail-closed guarantee at exhaustion.

Rustls advances `read_seq` only after a successful provider result. The receive
function has no corresponding local exhaustion guard. RECV-STEP therefore
requires `read_seq < u64::MAX`; proving that the surrounding protocol lifecycle
always establishes this condition remains open. RECV-FAIL covers all u64 counter
values because provider failure does not increment. These are different failure
semantics within the shared old-to-old-plus-one bound, not implementation
equivalence or a proof of the complete SPARK exhaustion contract.

The sequence-checking provider returns unchanged plaintext, an authentication
error, or a representative other error. The proofs cover the record layer's
control flow and bookkeeping around those outcomes; they do not prove a real
provider's plaintext, authentication, key/IV preservation, or side effects.
RECV-INACTIVE uses rustls's real invalid provider and checks passthrough for
Invalid/Prepared keys, which is a rustls-specific lifecycle property.

TRIAL-BUDGET proves rustls's optional early-data discard budget over full-width
usize values, including zero and MAX. A rejected record consumes budget only
for an authentication error that fits the remaining allowance. Insufficient
budget and other errors propagate without changing counters or budget.
SPARKTLS has no directly corresponding 0-RTT discard contract here; this is a
new accounting lemma rather than a translated SPARK theorem.

READ-KEY-RESET proves reset/activation and trial-mode setup/termination while
preserving the write counter and the historical `has_decrypted` flag. It does
not establish that newly installed cryptographic key material is fresh.

## DISC-006: TLSInnerPlaintext padding and type policy — PARTIAL

Both implementations locate the last nonzero byte as the inner content type and
preserve the preceding bytes. INNER-PADDING transfers that formula to the real
rustls unpadding function over every input of length 0..8. The specification
supplies a symbolic position for the last nonzero byte and constrains only the
input bytes to satisfy that definition.
Every nonzero input has exactly one such witness; None covers all-zero/empty
inputs. Rustls's implementation pops backward. Neither the proof nor the
shared byte-level result establishes constant-time execution.

Rustls rejects empty/all-zero inner plaintext at this boundary. SPARKTLS returns
AEAD success with an inner type of zero and leaves rejection to its caller.
Rustls also maps any nonzero byte to a ContentType, including Unknown values;
this proof does not imply that higher protocol layers accept those types.
Composition with the protocol's permitted-type checks is unported.

Rustls checks an inner-plaintext size limit before padding removal. That policy
and the SPARK encrypted-input limit occur at different stages and are not
claimed equivalent. INNER-LIMIT separately checks the documented size domain;
arbitrary large padded records remain outside the exhaustive byte domain.
