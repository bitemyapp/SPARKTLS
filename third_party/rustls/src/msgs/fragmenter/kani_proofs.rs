use super::*;

#[kani::proof]
#[kani::unwind(3)]
fn fragment_configuration_preserves_rfc_bound() {
    let previous: usize = kani::any();
    kani::assume((27..=MAX_FRAGMENT_LEN).contains(&previous));
    let requested: Option<usize> = kani::any();
    let mut fragmenter = MessageFragmenter { max_frag: previous };
    let result = fragmenter.set_max_fragment_size(requested);
    match requested {
        None => {
            assert!(result.is_ok());
            assert_eq!(fragmenter.max_frag, 16_384);
        }
        Some(size) if (32..=16_389).contains(&size) => {
            assert!(result.is_ok());
            assert_eq!(fragmenter.max_frag + 5, size);
        }
        Some(_) => {
            assert!(matches!(result, Err(Error::BadMaxFragmentSize)));
            assert_eq!(fragmenter.max_frag, previous);
        }
    }
    assert!((27..=16_384).contains(&fragmenter.max_frag));
}

#[kani::proof]
#[kani::unwind(67)]
fn fragment_partition_preserves_bytes_and_metadata() {
    let data: [u8; 64] = kani::any();
    let len: usize = kani::any();
    let limit: usize = kani::any();
    kani::assume(len <= data.len());
    kani::assume((27..=16_384).contains(&limit));
    let typ = ContentType::from(kani::any::<u8>());
    let version = ProtocolVersion::from(kani::any::<u16>());
    let fragmenter = MessageFragmenter { max_frag: limit };
    let mut fragments = fragmenter.fragment_payload(typ, version, (&data[..len]).into());
    let mut offset = 0;
    // At most ceil(64 / 27) = 3 fragments in this domain.
    // Checking termination after three steps is a postcondition, not an assumption.
    for _ in 0..3 {
        let Some(fragment) = fragments.next() else {
            break;
        };
        assert_eq!(fragment.typ, typ);
        assert_eq!(fragment.version, version);
        let OutboundChunks::Single(bytes) = fragment.payload else {
            unreachable!()
        };
        assert!(!bytes.is_empty());
        assert!(bytes.len() <= limit);
        assert!(bytes.len() <= 16_384);
        assert_eq!(bytes, &data[offset..offset + bytes.len()]);
        offset += bytes.len();
    }
    assert!(fragments.next().is_none());
    assert_eq!(offset, len);
}
