//! Case construction for `tests/admission_vectors.rs`: each case states the
//! rule it checks; the expected verdict is set here, not read from `admits`.
use companion_core::provider::approval_v2::{self as v2, APPROVAL_DOMAIN, ENROLL_DOMAIN};
use serde_json::Value;
use std::path::{Path, PathBuf};

const SYNTHETIC: &[u8] = b"dev.vaultwarden.companion.synthetic.v1";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn fields(transcript: &[u8]) -> Vec<Vec<u8>> {
    companion_core::provider::admission::fields(transcript)
        .unwrap()
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect()
}
fn frame(fields: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in fields {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}
fn flipped(mut value: Vec<u8>, index: usize) -> Vec<u8> {
    value[index] ^= 1;
    value
}

pub struct Golden {
    provider: String,
    client: String,
    key: Vec<u8>,
    approval: Vec<u8>,
    enroll: Vec<u8>,
}
pub fn golden() -> Golden {
    let text = std::fs::read_to_string(root().join("tests/fixtures/approval-v2-golden.json"));
    let g: Value = serde_json::from_str(&text.unwrap()).unwrap();
    let s = |path: &str| g.pointer(path).unwrap().as_str().unwrap().to_string();
    Golden {
        provider: s("/approval/provider_identity"),
        client: s("/approval/approval_client"),
        key: v2::base64url_decode(&s("/public_key")).unwrap(),
        approval: unhex(&s("/approval/transcript_hex")),
        enroll: unhex(&s("/enroll/transcript_hex")),
    }
}

/// `(name, purpose, provider, client, public key, transcript, admitted)`.
pub type Case = (String, &'static str, String, String, Vec<u8>, Vec<u8>, bool);

pub fn cases(g: &Golden) -> Vec<Case> {
    let case = |name: &str, purpose, transcript: Vec<u8>, admitted| -> Case {
        let (p, c, k) = (g.provider.clone(), g.client.clone(), g.key.clone());
        (name.into(), purpose, p, c, k, transcript, admitted)
    };
    let edit = |base: &[u8], index: usize, value: Vec<u8>| {
        let mut f = fields(base);
        f[index] = value;
        frame(&f)
    };
    let (a, e) = (fields(&g.approval), fields(&g.enroll));
    let mut out = vec![
        case("approve: golden", "approve", g.approval.clone(), true),
        case("enroll: golden", "enroll", g.enroll.clone(), true),
        case(
            "approve: an enrollment transcript",
            "approve",
            g.enroll.clone(),
            false,
        ),
        case(
            "enroll: an approval transcript",
            "enroll",
            g.approval.clone(),
            false,
        ),
    ];
    // Fields 5 to 13 (approve) and 4, 5 (enroll) are only sized: any value of
    // the right size is admitted; Rust and the provider own their meaning.
    let mut free = a.clone();
    for (index, field) in free.iter_mut().enumerate().skip(5) {
        *field = vec![index as u8 + b'A'; field.len()];
    }
    out.push(case(
        "approve: other request values",
        "approve",
        frame(&free),
        true,
    ));
    let mut free = e.clone();
    free[4] = vec![0x42; 32];
    free[5] = vec![b'Z'; 43];
    out.push(case(
        "enroll: other ticket and action id",
        "enroll",
        frame(&free),
        true,
    ));
    let approve_edits: Vec<(usize, Vec<u8>)> = vec![
        (0, SYNTHETIC.to_vec()),
        (0, ENROLL_DOMAIN.as_bytes().to_vec()),
        (1, b"deny".to_vec()),
        (2, flipped(a[2].clone(), 0)),
        (3, flipped(a[3].clone(), 0)),
        (4, flipped(a[4].clone(), 31)),
        (5, vec![b'A'; 42]),
    ];
    for (index, value) in approve_edits {
        let name = format!("approve: field {index} wrong");
        out.push(case(
            &name,
            "approve",
            edit(&g.approval, index, value),
            false,
        ));
    }
    for (index, field) in a.iter().enumerate().skip(6) {
        let name = format!("approve: field {index} one byte long");
        let longer = [field.clone(), vec![0]].concat();
        out.push(case(
            &name,
            "approve",
            edit(&g.approval, index, longer),
            false,
        ));
    }
    let enroll_edits: Vec<(usize, Vec<u8>)> = vec![
        (0, APPROVAL_DOMAIN.as_bytes().to_vec()),
        (1, flipped(e[1].clone(), 0)),
        (2, flipped(e[2].clone(), 0)),
        (3, flipped(e[3].clone(), 64)),
        (4, vec![0x42; 31]),
        (5, vec![b'Z'; 44]),
    ];
    for (index, value) in enroll_edits {
        let name = format!("enroll: field {index} wrong");
        out.push(case(&name, "enroll", edit(&g.enroll, index, value), false));
    }
    for (purpose, base) in [("approve", &g.approval), ("enroll", &g.enroll)] {
        let f = fields(base);
        let framing = [
            ("a trailing byte", [base.clone(), vec![0]].concat()),
            ("truncated", base[..base.len() - 1].to_vec()),
            (
                "an extra empty field",
                frame(&[f.clone(), vec![Vec::new()]].concat()),
            ),
            ("a field without its first", frame(&f[1..])),
            ("33 empty fields", frame(&vec![Vec::new(); 33])),
            (
                "over 4096 bytes",
                frame(&[f.clone(), vec![vec![0; 4096]]].concat()),
            ),
            ("empty", Vec::new()),
        ];
        for (what, transcript) in framing {
            out.push(case(
                &format!("{purpose}: {what}"),
                purpose,
                transcript,
                false,
            ));
        }
        let mut c = case(
            &format!("{purpose}: another provider"),
            purpose,
            base.clone(),
            false,
        );
        c.2 = "00".repeat(32);
        out.push(c);
        let mut c = case(
            &format!("{purpose}: another client"),
            purpose,
            base.clone(),
            false,
        );
        c.3 = "00".repeat(32);
        out.push(c);
        let mut c = case(
            &format!("{purpose}: another key"),
            purpose,
            base.clone(),
            false,
        );
        c.4 = flipped(g.key.clone(), 64);
        out.push(c);
        let mut c = case(
            &format!("{purpose}: a compressed-prefix key"),
            purpose,
            base.clone(),
            false,
        );
        c.4[0] = 0x03;
        out.push(c);
        let mut c = case(
            &format!("{purpose}: a 64-byte key"),
            purpose,
            base.clone(),
            false,
        );
        c.4.pop();
        out.push(c);
    }
    out
}
