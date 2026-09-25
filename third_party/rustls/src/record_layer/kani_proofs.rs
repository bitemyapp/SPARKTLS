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
