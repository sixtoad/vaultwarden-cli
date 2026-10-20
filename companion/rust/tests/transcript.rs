use companion_core::{
    api::{Operation, Work},
    lifecycle::transcript,
};

#[test]
fn shared_swift_rust_golden_vector() {
    let work = Work {
        token: 9,
        epoch: 7,
        operation: Operation::Sign,
        fixture: 1,
        expires_unix_ms: 1_700_000_000_000,
        nonce: vec![0x11; 32],
        key_id: vec![0x22; 32],
    };
    let actual: String = transcript(&work)
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        actual,
        include_str!("../../fixtures/transcript-v1.hex").trim()
    );
    let mut second = work.clone();
    second.fixture = 2;
    let actual: String = transcript(&second)
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        actual,
        include_str!("../../fixtures/transcript-v1-fixture-two.hex").trim()
    );
    let mut bad = work;
    bad.nonce.push(0);
    assert!(transcript(&bad).is_err());
}
