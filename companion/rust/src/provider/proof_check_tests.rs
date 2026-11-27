use super::*;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}
fn point(key: &SigningKey) -> Vec<u8> {
    key.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}
fn der(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let signature: Signature = key.sign(message);
    signature.to_der().as_bytes().to_vec()
}
fn signing(key: &SigningKey) -> SigningTranscript {
    SigningTranscript {
        key_id: v2::key_id(&point(key)),
        transcript: b"exact transcript bytes".to_vec(),
    }
}
fn hello_data(flags: u8) -> Vec<u8> {
    let mut data = key_class::rp_id_hash().to_vec();
    data.push(flags);
    data.extend_from_slice(&[0, 0, 0, 1]);
    data
}

#[test]
fn a_signature_over_the_exact_transcript_by_the_bound_key_is_accepted() {
    let k = key(7);
    let s = signing(&k);
    assert_eq!(
        approval_proof(&s, &point(&k), &der(&k, &s.transcript), None),
        Ok(())
    );
}

#[test]
fn another_key_or_a_malformed_point_is_refused() {
    let (k, other) = (key(7), key(8));
    let s = signing(&k);
    let signed_by_other = der(&other, &s.transcript);
    assert_eq!(
        approval_proof(&s, &point(&other), &signed_by_other, None),
        Err(BiometricRefusal::KeyMismatch)
    );
    let good = point(&k);
    let mut compressed = good.clone();
    compressed[0] = 0x03;
    let mut off_curve = good.clone();
    off_curve[64] ^= 1;
    for bad in [Vec::new(), good[..64].to_vec(), compressed, off_curve] {
        assert_eq!(
            approval_proof(&s, &bad, &der(&k, &s.transcript), None),
            Err(BiometricRefusal::InvalidPublicKey)
        );
    }
}

#[test]
fn a_signature_that_does_not_verify_over_these_bytes_is_refused() {
    let k = key(7);
    let s = signing(&k);
    let other_bytes = der(&k, b"exact transcript byteS");
    let raw = Signature::from_der(&der(&k, &s.transcript))
        .unwrap()
        .to_bytes()
        .to_vec();
    for bad in [other_bytes, raw, Vec::new(), vec![0x30; 73]] {
        assert_eq!(
            approval_proof(&s, &point(&k), &bad, None),
            Err(BiometricRefusal::InvalidSignature)
        );
    }
}

#[test]
fn a_windows_hello_proof_verifies_over_the_webauthn_message_only() {
    let k = key(7);
    let s = signing(&k);
    let data = hello_data(0x05);
    let message = key_class::signed_message(&s.transcript, &data).unwrap();
    let wrapped = der(&k, &message);
    assert_eq!(
        approval_proof(&s, &point(&k), &wrapped, Some(&data)),
        Ok(())
    );
    // The wrapped signature is not a raw one, nor the reverse.
    assert_eq!(
        approval_proof(&s, &point(&k), &wrapped, None),
        Err(BiometricRefusal::InvalidSignature)
    );
    let raw = der(&k, &s.transcript);
    assert_eq!(
        approval_proof(&s, &point(&k), &raw, Some(&data)),
        Err(BiometricRefusal::InvalidSignature)
    );
    // Data the provider refuses (UV clear, BE set, truncated) never verifies.
    for bad in [hello_data(0x01), hello_data(0x0d), data[..36].to_vec()] {
        assert_eq!(
            approval_proof(&s, &point(&k), &wrapped, Some(&bad)),
            Err(BiometricRefusal::InvalidSignature)
        );
    }
}

/// The strict-DER cases the Android signer used to check natively
/// (`SignatureEncoding.isStrictDer`), now held by the one Rust check.
#[test]
fn der_must_be_strict() {
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let int = |value: &[u8]| [&[0x02, value.len() as u8][..], value].concat();
    let seq = |parts: &[Vec<u8>]| {
        let body = parts.concat();
        [vec![0x30, body.len() as u8], body].concat()
    };
    let one = [1u8];
    let n = [&[0u8][..], &N].concat();
    let mut n_minus_one = n.clone();
    n_minus_one[32] -= 1;
    for good in [
        seq(&[int(&one), int(&one)]),
        seq(&[int(&[0, 0x80]), int(&one)]),
        seq(&[int(&n_minus_one), int(&n_minus_one)]),
    ] {
        assert!(v2::valid_signature(&good), "{good:02x?}");
    }
    let rejected = [
        seq(&[int(&[0]), int(&one)]),                     // zero
        seq(&[int(&[0x80]), int(&one)]),                  // negative
        seq(&[int(&[0, 1]), int(&one)]),                  // not minimal
        seq(&[int(&n), int(&one)]),                       // r = n
        [seq(&[int(&one), int(&one)]), vec![0]].concat(), // trailing
        seq(&[int(&one)]),                                // one integer
        [vec![0x31, 6], int(&one), int(&one)].concat(),   // not a sequence
        seq(&[int(&one), int(&one), int(&one)]),          // three integers
        vec![0; 73],
    ];
    for (index, bad) in rejected.iter().enumerate() {
        assert!(!v2::valid_signature(bad), "case {index}");
    }
}
