//! Approval-key classes (desktop-approval-spec D-7/D-8): Windows Hello keys
//! enroll with `biometric_enroll` version 3 and prove with WebAuthn-wrapped
//! signatures; every existing (`biometric`) rule is unchanged. Software
//! P-256 keys stand in for the Windows Hello credential.
use super::*;
use crate::access::approval_key_class::{self as class, KeyClass};
use sha2::{Digest, Sha256};

const UP_UV: u8 = 0x05;

fn authenticator_data(flags: u8) -> Vec<u8> {
    let mut data = Sha256::digest(class::WEBAUTHN_RP_ID.as_bytes()).to_vec();
    data.push(flags);
    data.extend_from_slice(&0u32.to_be_bytes());
    data
}
/// What Windows Hello signs: `authenticatorData || SHA-256(clientData)`.
fn hello_sign(key: &EcdsaKeyPair, transcript: &[u8], data: &[u8]) -> Vec<u8> {
    let mut message = data.to_vec();
    message.extend_from_slice(&Sha256::digest(class::client_data(transcript)));
    sign(key, &message)
}
fn v3_enroll(
    prepared: &serde_json::Value,
    public_key: &[u8],
    signature: &[u8],
    key_class: Option<KeyClass>,
    data: Option<&[u8]>,
) -> Command {
    let Command::BiometricEnroll {
        action_id,
        ticket,
        password,
        public_key,
        enroll_signature,
        ..
    } = enroll_command(prepared, public_key, signature, PASSWORD)
    else {
        panic!("the helper builds this command")
    };
    Command::BiometricEnroll {
        version: 3,
        action_id,
        ticket,
        password,
        public_key,
        enroll_signature,
        key_class,
        enroll_authenticator_data: data.map(|d| URL_SAFE_NO_PAD.encode(d)),
    }
}
impl Svc {
    fn enroll_transcript_for(
        &self,
        device: &str,
        key: &EcdsaKeyPair,
    ) -> (serde_json::Value, Vec<u8>) {
        let prepared = body(&self.prepare(device, management::BiometricOperation::Enroll, device));
        let transcript = v2::enroll_transcript(
            prepared["provider_identity"].as_str().unwrap(),
            device,
            key.public_key().as_ref(),
            prepared["ticket"].as_str().unwrap(),
            prepared["action_id"].as_str().unwrap(),
        )
        .unwrap();
        (prepared, transcript)
    }
    fn enroll_hello(&self, key: &EcdsaKeyPair) -> String {
        let (prepared, transcript) = self.enroll_transcript_for(&me(), key);
        let data = authenticator_data(UP_UV);
        let response = self.send(
            &me(),
            v3_enroll(
                &prepared,
                key.public_key().as_ref(),
                &hello_sign(key, &transcript, &data),
                Some(KeyClass::WindowsHello),
                Some(&data),
            ),
        );
        assert_eq!(response.status, 200, "{}", response.body);
        body(&response)["biometric_key_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}
fn hello_proof(
    id: &str,
    ticket: &str,
    key_id: &str,
    signature: &[u8],
    data: Option<&[u8]>,
) -> Command {
    let Command::Decision {
        version,
        request_id,
        ticket,
        decision,
        password,
        proof: Some(mut proof),
    } = proof(id, ticket, key_id, signature)
    else {
        panic!("the helper builds this command")
    };
    proof.authenticator_data = data.map(|d| URL_SAFE_NO_PAD.encode(d));
    Command::Decision {
        version,
        request_id,
        ticket,
        decision,
        password,
        proof: Some(proof),
    }
}
fn registry_version(s: &Svc) -> serde_json::Value {
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&s.service.identity_store).unwrap()).unwrap();
    raw["version"].clone()
}

#[test]
fn key_class_windows_hello_enrolls_approves_and_is_recorded_as_windows_hello() {
    let s = setup(false);
    let key = software_key();
    let key_id = s.enroll_hello(&key);
    assert_eq!(key_id, v2::key_id(key.public_key().as_ref()));
    assert_eq!(registry_version(&s), 4);
    let enrolled = identity::biometric_key(&s.service.identity_store, &me())
        .unwrap()
        .unwrap();
    assert_eq!(enrolled.class, KeyClass::WindowsHello);
    let id = s.request();
    let review = s.review(&id);
    assert_eq!(review["approval_binding"]["biometric_allowed"], true);
    let transcript = companion_transcript(&review, &key_id);
    let data = authenticator_data(UP_UV);
    let response = s.send(
        &me(),
        hello_proof(
            &id,
            &ticket(&review),
            &key_id,
            &hello_sign(&key, &transcript, &data),
            Some(&data),
        ),
    );
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(s.status(&id), DirectStatus::Approved);
    let history = s.env.app().companion_history(None).unwrap();
    let approved = history
        .iter()
        .find(|e| e.request_id == id && e.outcome == HistoryOutcome::Approved)
        .unwrap();
    assert_eq!(
        approved.approval,
        Some(ApprovalMethod::WindowsHello {
            key_id: key_id.clone()
        })
    );
    let wire = serde_json::to_value(approved).unwrap();
    assert_eq!(
        wire["approval"],
        serde_json::json!({"method":"windows_hello","key_id":key_id})
    );
    // Revoking the last Windows Hello key returns the registry to version 3.
    assert_eq!(revoke_key(&s, &me(), &me()).status, 200);
    assert_eq!(registry_version(&s), 3);
}

#[test]
fn key_class_proof_shape_must_match_the_enrolled_class() {
    // A Windows Hello key never verifies a raw transcript signature, nor a
    // wrapping whose flags lack user verification or name another RP.
    let s = setup(false);
    let key = software_key();
    let key_id = s.enroll_hello(&key);
    // `wrap`: the authenticator data the key signs over (empty: a raw
    // transcript signature); `data`: the authenticator data sent.
    let refused = |wrap: Vec<u8>, data: Option<Vec<u8>>| {
        s.cool();
        let id = s.request();
        let review = s.review(&id);
        let transcript = companion_transcript(&review, &key_id);
        let signature = if wrap.is_empty() {
            sign(&key, &transcript)
        } else {
            hello_sign(&key, &transcript, &wrap)
        };
        s.send(
            &me(),
            hello_proof(&id, &ticket(&review), &key_id, &signature, data.as_deref()),
        )
        .status
    };
    assert_eq!(refused(Vec::new(), None), 422);
    assert_eq!(refused(Vec::new(), Some(authenticator_data(UP_UV))), 422);
    for flags in [0x01, 0x04, 0x0d, 0x15, 0x45, 0x85] {
        let data = authenticator_data(flags);
        assert_eq!(refused(data.clone(), Some(data)), 422, "flags {flags:#x}");
    }
    let mut other_rp = authenticator_data(UP_UV);
    other_rp[3] ^= 0x40;
    assert_eq!(refused(other_rp.clone(), Some(other_rp)), 422);
    // Malformed authenticator data is not even a valid command.
    assert_eq!(refused(authenticator_data(UP_UV), Some(vec![5; 36])), 400);
    assert_eq!(s.dispatch.0.load(Ordering::SeqCst), 0);
    // Control: the same harness with the right wrapping approves.
    let good = authenticator_data(UP_UV);
    assert_eq!(refused(good.clone(), Some(good)), 200);
    assert_eq!(s.dispatch.0.load(Ordering::SeqCst), 1);

    // A biometric key never accepts a wrapped proof.
    let s = setup(false);
    let key = software_key();
    let key_id = s.enroll(&key);
    let id = s.request();
    let review = s.review(&id);
    let transcript = companion_transcript(&review, &key_id);
    let data = authenticator_data(UP_UV);
    let response = s.send(
        &me(),
        hello_proof(
            &id,
            &ticket(&review),
            &key_id,
            &hello_sign(&key, &transcript, &data),
            Some(&data),
        ),
    );
    assert_eq!(response.status, 422);
    assert_eq!(s.status(&id), DirectStatus::Pending);
}

#[test]
fn key_class_enrollment_versions_are_closed() {
    let s = setup(false);
    let key = software_key();
    let public_key = key.public_key().as_ref().to_vec();
    let (prepared, transcript) = s.enroll_transcript_for(&me(), &key);
    let data = authenticator_data(UP_UV);
    let hello = hello_sign(&key, &transcript, &data);
    let raw = sign(&key, &transcript);
    // Version 2 with any class member, version 3 without a class, with the
    // implicit `biometric` class or without authenticator data: invalid.
    let mut v2_with_class = enroll_command(&prepared, &public_key, &raw, PASSWORD);
    if let Command::BiometricEnroll { key_class, .. } = &mut v2_with_class {
        *key_class = Some(KeyClass::WindowsHello);
    }
    for command in [
        v2_with_class,
        v3_enroll(&prepared, &public_key, &hello, None, Some(&data)),
        v3_enroll(
            &prepared,
            &public_key,
            &raw,
            Some(KeyClass::Biometric),
            None,
        ),
        v3_enroll(
            &prepared,
            &public_key,
            &raw,
            Some(KeyClass::Biometric),
            Some(&data),
        ),
        v3_enroll(
            &prepared,
            &public_key,
            &hello,
            Some(KeyClass::WindowsHello),
            None,
        ),
        v3_enroll(
            &prepared,
            &public_key,
            &hello,
            Some(KeyClass::WindowsHello),
            Some(&data[..36]),
        ),
    ] {
        assert!(!command.valid());
    }
    let mut v4 = v3_enroll(
        &prepared,
        &public_key,
        &hello,
        Some(KeyClass::WindowsHello),
        Some(&data),
    );
    if let Command::BiometricEnroll { version, .. } = &mut v4 {
        *version = 4;
    }
    assert!(!v4.valid());
    // Unknown classes are refused by the parser.
    let json = serde_json::json!({"version":3,"command":"biometric_enroll","action_id":prepared["action_id"],
        "ticket":prepared["ticket"],"password":PASSWORD,"public_key":URL_SAFE_NO_PAD.encode(&public_key),
        "enroll_signature":URL_SAFE_NO_PAD.encode(&hello),"key_class":"tpm","enroll_authenticator_data":URL_SAFE_NO_PAD.encode(&data)});
    assert!(serde_json::from_value::<Command>(json).is_err());
    // A raw signature, or a wrapping without user verification, never
    // proves possession for a Windows Hello key.
    for (signature, flags) in [
        (raw.clone(), UP_UV),
        (
            hello_sign(&key, &transcript, &authenticator_data(0x01)),
            0x01,
        ),
    ] {
        s.cool();
        let (prepared, _) = s.enroll_transcript_for(&me(), &key);
        let response = s.send(
            &me(),
            v3_enroll(
                &prepared,
                &public_key,
                &signature,
                Some(KeyClass::WindowsHello),
                Some(&authenticator_data(flags)),
            ),
        );
        assert_ne!(response.status, 200, "flags {flags:#x}");
    }
    assert!(
        identity::biometric_key(&s.service.identity_store, &me())
            .unwrap()
            .is_none()
    );
    // The biometric (version 2) path is untouched.
    s.cool();
    s.enroll(&key);
    assert_eq!(registry_version(&s), 3);
}

#[test]
fn key_class_registry_refuses_a_class_below_version_4_and_unknown_classes() {
    let s = setup(false);
    let key = software_key();
    s.enroll_hello(&key);
    let path = s.service.identity_store.clone();
    let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(raw["biometric"][0]["key_class"], "windows_hello");
    let write = |value: serde_json::Value| {
        std::fs::write(&path, value.to_string()).unwrap();
        identity::enrolled(&path)
    };
    let mut v3 = raw.clone();
    v3["version"] = 3.into();
    assert!(write(v3).is_err());
    let mut unknown = raw.clone();
    unknown["biometric"][0]["key_class"] = "tpm".into();
    assert!(write(unknown).is_err());
    let mut v5 = raw.clone();
    v5["version"] = 5.into();
    assert!(write(v5).is_err());
    assert!(write(raw).is_ok());
}
