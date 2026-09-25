//! Provider-independent sequence/lifecycle contracts. The sequence-checking
//! provider below is only a test double; it does not prove AEAD correctness.
use super::*;
use crate::enums::{ContentType, ProtocolVersion};
use crate::msgs::message::OutboundChunks;

struct SequenceCheckingEncrypter {
    expected: u64,
}

impl MessageEncrypter for SequenceCheckingEncrypter {
    fn encrypt(
        &mut self,
        message: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        assert_eq!(seq, self.expected);
        Ok(message.to_unencrypted_opaque())
    }

    fn encrypted_payload_len(&self, len: usize) -> usize {
        len
    }
}

#[kani::proof]
#[kani::unwind(8)]
fn write_sequence_policy_prevents_wrap() {
    let mut layer = RecordLayer::new();
    let max_messages: u64 = kani::any();
    layer.prepare_message_encrypter(<dyn MessageEncrypter>::invalid(), max_messages);
    let seq: u64 = kani::any();
    let add: u64 = kani::any();
    layer.write_seq = seq;
    let action = layer.pre_encrypt_action(add);
    let mathematical_sum = u128::from(seq) + u128::from(add);
    if mathematical_sum >= u128::from(SEQ_HARD_LIMIT) {
        assert_eq!(action, PreEncryptAction::Refuse);
    }
    if layer.next_pre_encrypt_action() != PreEncryptAction::Refuse {
        assert!(seq < SEQ_HARD_LIMIT);
        assert!(seq.checked_add(1).is_some());
    }
    assert_eq!(layer.write_seq, seq);
}

#[kani::proof]
#[kani::unwind(10)]
fn outgoing_record_uses_old_sequence_then_increments_once() {
    let seq: u64 = kani::any();
    kani::assume(seq < SEQ_HARD_LIMIT);
    let mut layer = RecordLayer::new();
    layer.set_message_encrypter(
        Box::new(SequenceCheckingEncrypter { expected: seq }),
        u64::MAX,
    );
    layer.write_seq = seq;
    let old_read_seq: u64 = kani::any();
    layer.read_seq = old_read_seq;
    let message = OutboundPlainMessage {
        typ: ContentType::ApplicationData,
        version: ProtocolVersion::TLSv1_2,
        payload: OutboundChunks::new_empty(),
    };
    let _ = layer.encrypt_outgoing(message);
    assert_eq!(layer.write_seq(), seq + 1);
    assert_eq!(layer.read_seq(), old_read_seq);
    assert!(layer.is_encrypting());
}

#[kani::proof]
#[kani::unwind(8)]
fn installing_write_key_resets_sequence_and_caps_limit() {
    let mut layer = RecordLayer::new();
    layer.write_seq = kani::any();
    layer.read_seq = kani::any();
    let old_read_seq = layer.read_seq;
    let max_messages: u64 = kani::any();
    layer.prepare_message_encrypter(<dyn MessageEncrypter>::invalid(), max_messages);
    assert_eq!(layer.write_seq(), 0);
    assert_eq!(layer.read_seq(), old_read_seq);
    assert_eq!(layer.write_seq_max, max_messages.min(SEQ_SOFT_LIMIT));
    assert!(layer.encrypt_state == DirectionState::Prepared);
    assert!(!layer.is_encrypting());
    layer.start_encrypting();
    assert!(layer.is_encrypting());
    assert_eq!(layer.write_seq(), 0);
}

// These outcomes model only the provider boundary. They do not authenticate
// ciphertext, implement AEAD, or stand in for an analysis of the native backend.
enum DecryptionOutcome {
    Accept,
    AuthenticationFailure,
    OtherFailure,
}

struct SequenceCheckingDecrypter {
    expected: u64,
    outcome: DecryptionOutcome,
}

impl MessageDecrypter for SequenceCheckingDecrypter {
    fn decrypt<'a>(
        &mut self,
        message: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        kani::assert(
            seq == self.expected,
            "receive provider sees the old sequence",
        );
        match self.outcome {
            DecryptionOutcome::Accept => Ok(message.into_plain_message()),
            DecryptionOutcome::AuthenticationFailure => Err(Error::DecryptError),
            DecryptionOutcome::OtherFailure => Err(Error::PeerSentOversizedRecord),
        }
    }
}

#[kani::proof]
#[kani::unwind(19)]
fn incoming_success_advances_once_and_preserves_plaintext() {
    let seq: u64 = kani::any();
    // Unlike SPARKTLS, this rustls function has no local exhaustion guard.
    // This precondition is explicit; caller/lifecycle exhaustion is unproved.
    kani::assume(seq < u64::MAX);
    let mut layer = RecordLayer::new();
    layer.set_message_decrypter(Box::new(SequenceCheckingDecrypter {
        expected: seq,
        outcome: DecryptionOutcome::Accept,
    }));
    layer.read_seq = seq;
    layer.write_seq = kani::any();
    layer.has_decrypted = kani::any();
    layer.trial_decryption_len = kani::any();
    let old_write = layer.write_seq;
    let old_budget = layer.trial_decryption_len;
    let original: [u8; 16] = kani::any();
    let mut bytes = original;
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let typ = ContentType::from(kani::any::<u8>());
    let version = ProtocolVersion::from(kani::any::<u16>());
    let result = layer.decrypt_incoming(InboundOpaqueMessage::new(typ, version, &mut bytes[..len]));
    let Ok(Some(result)) = result else {
        kani::assert(false, "receive returns the expected plaintext");
        return;
    };
    kani::assert(
        layer.read_seq() == seq + 1,
        "successful receive advances sequence once",
    );
    assert!(layer.write_seq() == old_write);
    assert!(layer.has_decrypted());
    assert!(layer.trial_decryption_len == old_budget);
    assert!(result.want_close_before_decrypt == (seq == SEQ_SOFT_LIMIT));
    assert!(result.plaintext.typ == typ);
    assert!(result.plaintext.version == version);
    assert!(result.plaintext.payload.len() == len);
    // A symbolic index proves every byte without a slice-equality loop.
    let index: usize = kani::any();
    kani::assume(index < original.len());
    if index < len {
        kani::assert(
            result.plaintext.payload[index] == original[index],
            "receive preserves every plaintext byte",
        );
    }
    kani::assert(
        bytes[index] == original[index],
        "receive preserves backing storage",
    );
}

#[kani::proof]
#[kani::unwind(5)]
fn incoming_failure_preserves_sequence_and_obeys_trial_budget() {
    let seq: u64 = kani::any();
    let authentication_failure: bool = kani::any();
    let mut layer = RecordLayer::new();
    layer.set_message_decrypter(Box::new(SequenceCheckingDecrypter {
        expected: seq,
        outcome: if authentication_failure {
            DecryptionOutcome::AuthenticationFailure
        } else {
            DecryptionOutcome::OtherFailure
        },
    }));
    layer.read_seq = seq;
    layer.write_seq = kani::any();
    layer.has_decrypted = kani::any();
    let old_write = layer.write_seq;
    let old_has_decrypted = layer.has_decrypted;
    let budget: Option<usize> = kani::any();
    layer.trial_decryption_len = budget;
    let len: usize = kani::any();
    let mut bytes = [0u8; 32];
    kani::assume(len <= bytes.len());
    let result = layer.decrypt_incoming(InboundOpaqueMessage::new(
        ContentType::ApplicationData,
        ProtocolVersion::TLSv1_2,
        &mut bytes[..len],
    ));
    let may_drop = authentication_failure && budget.is_some_and(|b| b >= len);
    if may_drop {
        assert!(matches!(result, Ok(None)));
        assert!(layer.trial_decryption_len == Some(budget.unwrap() - len));
    } else {
        if authentication_failure {
            assert!(matches!(result, Err(Error::DecryptError)));
        } else {
            assert!(matches!(result, Err(Error::PeerSentOversizedRecord)));
        }
        assert!(layer.trial_decryption_len == budget);
    }
    kani::assert(layer.read_seq() == seq, "failed receive preserves sequence");
    assert!(layer.write_seq() == old_write);
    assert!(layer.has_decrypted() == old_has_decrypted);
    assert!(layer.decrypt_state == DirectionState::Active);
}

#[kani::proof]
#[kani::unwind(5)]
fn trial_decryption_budget_never_underflows() {
    let mut layer = RecordLayer::new();
    let budget: Option<usize> = kani::any();
    let requested: usize = kani::any();
    layer.trial_decryption_len = budget;
    let consumed = layer.doing_trial_decryption(requested);
    match budget {
        Some(before) if before >= requested => {
            assert!(consumed);
            let after = layer.trial_decryption_len.unwrap();
            assert!(after as u128 + requested as u128 == before as u128);
            assert!(after <= before);
        }
        _ => {
            assert!(!consumed);
            assert!(layer.trial_decryption_len == budget);
        }
    }
    layer.finish_trial_decryption();
    assert!(!layer.doing_trial_decryption(requested));
    assert!(layer.trial_decryption_len == None);
}

#[kani::proof]
#[kani::unwind(19)]
fn inactive_receive_preserves_counters_and_bytes() {
    // Constant calls cover both states without merging their provider objects.
    check_inactive_receive(false);
    check_inactive_receive(true);
}

fn check_inactive_receive(prepared: bool) {
    let mut layer = RecordLayer::new();
    if prepared {
        layer.prepare_message_decrypter(<dyn MessageDecrypter>::invalid());
    }
    layer.read_seq = kani::any();
    layer.write_seq = kani::any();
    layer.has_decrypted = kani::any();
    layer.trial_decryption_len = kani::any();
    let old_read = layer.read_seq;
    let old_write = layer.write_seq;
    let old_has_decrypted = layer.has_decrypted;
    let old_budget = layer.trial_decryption_len;
    let original: [u8; 16] = kani::any();
    let mut bytes = original;
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let typ = ContentType::from(kani::any::<u8>());
    let version = ProtocolVersion::from(kani::any::<u16>());
    // The installed invalid provider would return an error if called.
    let result = layer.decrypt_incoming(InboundOpaqueMessage::new(typ, version, &mut bytes[..len]));
    let Ok(Some(result)) = result else {
        kani::assert(false, "receive returns the expected plaintext");
        return;
    };
    assert!(!result.want_close_before_decrypt);
    assert!(result.plaintext.typ == typ);
    assert!(result.plaintext.version == version);
    assert!(result.plaintext.payload.len() == len);
    let index: usize = kani::any();
    kani::assume(index < original.len());
    if index < len {
        kani::assert(
            result.plaintext.payload[index] == original[index],
            "inactive receive preserves every plaintext byte",
        );
    }
    assert!(layer.read_seq() == old_read);
    assert!(layer.write_seq() == old_write);
    assert!(layer.has_decrypted() == old_has_decrypted);
    assert!(layer.trial_decryption_len == old_budget);
    kani::assert(
        bytes[index] == original[index],
        "inactive receive preserves backing storage",
    );
}

#[kani::proof]
#[kani::unwind(8)]
fn installing_read_key_resets_sequence_and_controls_trial_mode() {
    let mut layer = RecordLayer::new();
    layer.read_seq = kani::any();
    layer.write_seq = kani::any();
    layer.has_decrypted = kani::any();
    layer.trial_decryption_len = kani::any();
    let old_write = layer.write_seq;
    let old_has_decrypted = layer.has_decrypted;
    let old_budget = layer.trial_decryption_len;
    layer.prepare_message_decrypter(<dyn MessageDecrypter>::invalid());
    assert!(layer.read_seq() == 0);
    assert!(layer.decrypt_state == DirectionState::Prepared);
    assert!(layer.trial_decryption_len == old_budget);
    layer.start_decrypting();
    assert!(layer.decrypt_state == DirectionState::Active);
    assert!(layer.read_seq() == 0);
    let new_budget: Option<usize> = kani::any();
    // Model another key installation after arbitrary intervening records.
    layer.read_seq = kani::any();
    match new_budget {
        Some(max_length) => layer.set_message_decrypter_with_trial_decryption(
            <dyn MessageDecrypter>::invalid(),
            max_length,
        ),
        None => layer.set_message_decrypter(<dyn MessageDecrypter>::invalid()),
    }
    assert!(layer.decrypt_state == DirectionState::Active);
    assert!(layer.read_seq() == 0);
    assert!(layer.trial_decryption_len == new_budget);
    assert!(layer.write_seq() == old_write);
    assert!(layer.has_decrypted() == old_has_decrypted);
    layer.finish_trial_decryption();
    assert!(layer.trial_decryption_len == None);
    assert!(layer.read_seq() == 0);
}
