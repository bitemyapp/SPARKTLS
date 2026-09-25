//! Bounded contracts mapped in verification/rustls/COVERAGE.md.
//! Calls the real vendored implementation; no production function is stubbed.

use crate::crypto::cipher::{make_tls13_aad, Iv, Nonce};
use crate::msgs::codec::{put_u16, Codec, Reader};
use crate::msgs::message::{read_opaque_message_header, OutboundOpaqueMessage};

#[kani::proof]
#[kani::unwind(14)]
fn nonce_matches_spark_xor_encoding() {
    let iv: [u8; 12] = kani::any();
    let seq: u64 = kani::any();
    let actual = Nonce::new(&Iv::from(iv), seq).0;
    for i in 0..12 {
        let mask = if i < 4 {
            0
        } else {
            ((seq >> (8 * (11 - i))) & 255) as u8
        };
        kani::assert(
            actual[i] == (iv[i] ^ mask),
            "nonce differs from SPARK IV XOR counter encoding",
        );
    }
}

#[kani::proof]
#[kani::unwind(14)]
fn nonce_is_injective_for_a_fixed_iv() {
    let iv: [u8; 12] = kani::any();
    let first: u64 = kani::any();
    let second: u64 = kani::any();
    kani::assume(first != second);
    let iv = Iv::from(iv);
    assert_ne!(Nonce::new(&iv, first).0, Nonce::new(&iv, second).0);
}

#[kani::proof]
#[kani::unwind(8)]
fn tls13_aad_matches_spark_record_header() {
    let plaintext_len: u16 = kani::any();
    kani::assume(plaintext_len <= 16_384);
    let encrypted_len = usize::from(plaintext_len) + 1 + 16;
    let aad = make_tls13_aad(encrypted_len);
    assert_eq!(&aad[..3], &[0x17, 0x03, 0x03]);
    assert_eq!(
        usize::from(aad[3]) * 256 + usize::from(aad[4]),
        encrypted_len
    );
}

#[kani::proof]
#[kani::unwind(5)]
fn u16_codec_matches_spark_ts16() {
    let value: u16 = kani::any();
    let mut encoded = [0; 2];
    put_u16(value, &mut encoded);
    assert_eq!(encoded[0], (value / 256) as u8);
    assert_eq!(encoded[1], (value % 256) as u8);
    let mut reader = Reader::init(&encoded);
    assert_eq!(u16::read(&mut reader).unwrap(), value);
    assert_eq!(reader.used(), 2);
    assert_eq!(reader.left(), 0);
}

#[kani::proof]
#[kani::unwind(35)]
fn reader_take_preserves_accounting() {
    let data: [u8; 32] = kani::any();
    let len: usize = kani::any();
    let start: usize = kani::any();
    let amount: usize = kani::any();
    kani::assume(len <= data.len());
    kani::assume(start <= len);
    let mut reader = Reader::init(&data[..len]);
    assert!(reader.take(start).is_some());
    match reader.take(amount) {
        Some(part) => {
            assert!(amount <= len - start);
            assert_eq!(part, &data[start..start + amount]);
            assert_eq!(reader.used(), start + amount);
        }
        None => {
            assert!(amount > len - start);
            assert_eq!(reader.used(), start);
        }
    }
    assert_eq!(reader.used() + reader.left(), len);
    assert_eq!(reader.any_left(), reader.left() != 0);
}

#[kani::proof]
#[kani::unwind(35)]
fn reader_sub_and_rest_preserve_bytes() {
    let data: [u8; 32] = kani::any();
    let len: usize = kani::any();
    let amount: usize = kani::any();
    kani::assume(len <= data.len());
    let mut reader = Reader::init(&data[..len]);
    match reader.sub(amount) {
        Ok(mut sub) => {
            assert!(amount <= len);
            assert_eq!(sub.used(), 0);
            assert_eq!(sub.rest(), &data[..amount]);
            assert_eq!(sub.left(), 0);
            assert_eq!(reader.rest(), &data[amount..len]);
        }
        Err(_) => {
            assert!(amount > len);
            assert_eq!(reader.used(), 0);
            assert_eq!(reader.rest(), &data[..len]);
        }
    }
    assert_eq!(reader.used(), len);
    assert!(reader.expect_empty("proof").is_ok());
}

// This verifies rustls's generic header policy, not SPARKTLS's stricter
// TLS-1.3 policy. Differences are explicit in DISCREPANCIES.md.
#[kani::proof]
#[kani::unwind(8)]
fn opaque_header_decodes_fields_and_policy() {
    let bytes: [u8; 5] = kani::any();
    let typ = bytes[0];
    let version = u16::from(bytes[1]) * 256 + u16::from(bytes[2]);
    let len = u16::from(bytes[3]) * 256 + u16::from(bytes[4]);
    let known_version = matches!(version, 0x0002 | 0xfeff | 0xfefd | 0xfefc);
    let accepted = (0x14..=0x18).contains(&typ)
        && (bytes[1] == 3 || known_version)
        && (typ == 0x17 || len != 0)
        && len < 18_432;
    let mut reader = Reader::init(&bytes);
    let result = read_opaque_message_header(&mut reader);
    assert_eq!(result.is_ok(), accepted);
    if let Ok((t, v, n)) = result {
        assert_eq!(u8::from(t), typ);
        assert_eq!(u16::from(v), version);
        assert_eq!(n, len);
        assert_eq!(reader.used(), 5);
    }
    assert!(reader.used() <= 5);
}

#[kani::proof]
#[kani::unwind(36)]
fn opaque_record_success_fits_available_buffer() {
    let bytes: [u8; 32] = kani::any();
    let available: usize = kani::any();
    kani::assume(available <= bytes.len());
    let mut reader = Reader::init(&bytes[..available]);
    if let Ok(record) = OutboundOpaqueMessage::read(&mut reader) {
        let n = record.payload.as_ref().len();
        assert_eq!(reader.used(), 5 + n);
        assert!(reader.used() <= available);
        assert!(n < 18_432);
        assert_eq!(record.payload.as_ref(), &bytes[5..5 + n]);
    }
    assert!(reader.used() <= available);
}
