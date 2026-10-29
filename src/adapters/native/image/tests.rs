use super::*;
fn put(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn command(kind: u32, prefix: usize, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; (prefix + value.len() + 1).div_ceil(8) * 8];
    let len = bytes.len() as u32;
    put(&mut bytes, 0, kind);
    put(&mut bytes, 4, len);
    put(&mut bytes, 8, prefix as u32);
    bytes[prefix..prefix + value.len()].copy_from_slice(value);
    bytes
}
fn thin(commands: &[Vec<u8>]) -> Vec<u8> {
    let size: usize = commands.iter().map(Vec::len).sum();
    let mut bytes = vec![0; 32];
    put(&mut bytes, 0, 0xfeedfacf);
    put(&mut bytes, 4, 0x0100000c);
    put(&mut bytes, 12, 2);
    put(&mut bytes, 16, commands.len() as u32);
    put(&mut bytes, 20, size as u32);
    for command in commands {
        bytes.extend_from_slice(command);
    }
    let mut p = 32;
    for command in commands {
        if word(command, 0).unwrap() == 0x1d {
            put(&mut bytes, p + 8, (32 + size) as u32);
        }
        p += command.len();
    }
    bytes.extend_from_slice(&[0; 16]);
    bytes
}
fn signed_commands() -> Vec<Vec<u8>> {
    let mut signature = vec![0; 16];
    put(&mut signature, 0, 0x1d);
    put(&mut signature, 4, 16);
    put(&mut signature, 12, 16);
    vec![command(0xe, 12, b"/usr/lib/dyld"), signature]
}
fn fat(slices: &[Vec<u8>], wide: bool) -> Vec<u8> {
    let stride = if wide { 32 } else { 20 };
    let mut bytes = vec![0; 8 + stride * slices.len()];
    bytes[..4].copy_from_slice(&(if wide { 0xcafebabfu32 } else { 0xcafebabeu32 }).to_be_bytes());
    bytes[4..8].copy_from_slice(&(slices.len() as u32).to_be_bytes());
    for (index, slice) in slices.iter().enumerate() {
        let p = 8 + index * stride;
        let offset = bytes.len();
        bytes[p..p + 4].copy_from_slice(&0x0100000cu32.to_be_bytes());
        if wide {
            bytes[p + 8..p + 16].copy_from_slice(&(offset as u64).to_be_bytes());
            bytes[p + 16..p + 24].copy_from_slice(&(slice.len() as u64).to_be_bytes());
        } else {
            bytes[p + 8..p + 12].copy_from_slice(&(offset as u32).to_be_bytes());
            bytes[p + 12..p + 16].copy_from_slice(&(slice.len() as u32).to_be_bytes());
        }
        bytes.extend_from_slice(slice);
    }
    bytes
}
#[test]
fn native_loader_profile_rejects_forbidden_unknown_and_malformed_commands() {
    let valid = signed_commands();
    assert!(macho(&thin(&valid)).is_ok());
    let mut dependency = valid.clone();
    dependency.push(command(0xc, 24, b"/usr/lib/libSystem.B.dylib"));
    assert!(macho(&thin(&dependency)).is_ok());
    let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
    for kind in [0x8000001c, 0x27, 0x10, 0x20, 0xf, 0x12345678] {
        let mut commands = valid.clone();
        commands.push(command(kind, 12, b"synthetic"));
        cases.push((format!("forbidden/unknown {kind:x}"), thin(&commands)));
    }
    for path in [
        b"/usr/lib/not-a-real-library-vw49.dylib".as_slice(),
        b"/tmp/custom.dylib",
        b"@rpath/custom.dylib",
        b"/usr/lib/../lib/custom.dylib",
    ] {
        let mut commands = valid.clone();
        commands.push(command(0xc, 24, path));
        cases.push((
            format!("dependency {}", String::from_utf8_lossy(path)),
            thin(&commands),
        ));
    }
    cases.push(("missing loader".into(), thin(&valid[1..])));
    cases.push(("missing signature".into(), thin(&valid[..1])));
    let mut duplicate = valid.clone();
    duplicate.push(valid[0].clone());
    cases.push(("duplicate loader".into(), thin(&duplicate)));
    duplicate = valid.clone();
    duplicate.push(valid[1].clone());
    cases.push(("duplicate signature".into(), thin(&duplicate)));
    let mut unterminated = valid.clone();
    unterminated[0] = command(0xe, 19, b"/usr/lib/dyld");
    unterminated[0].truncate(32);
    put(&mut unterminated[0], 4, 32);
    cases.push(("unterminated loader".into(), thin(&unterminated)));
    let mut alternate = valid.clone();
    alternate[0] = command(0xe, 12, b"/tmp/dyld");
    cases.push(("alternate loader".into(), thin(&alternate)));
    for (label, offset, value) in [
        ("unaligned command", 36, 9),
        ("zero command", 36, 0),
        ("out of bounds command", 36, 4096),
        ("bad loader offset", 40, 999),
        ("too many commands", 16, 4097),
        ("truncated commands", 20, 4096),
        ("signature before commands", 72, 0),
        ("signature overflow", 76, u32::MAX),
    ] {
        let mut bytes = thin(&valid);
        put(&mut bytes, offset, value);
        cases.push((label.into(), bytes));
    }
    for (label, bytes) in cases {
        assert!(macho(&bytes).is_err(), "{label}");
    }
}
#[test]
fn native_fat_and_fat64_slice_bounds_types_and_overlap_are_checked() {
    let thin = thin(&signed_commands());
    for wide in [false, true] {
        let valid = fat(&[thin.clone(), thin.clone()], wide);
        assert_eq!(macho(&valid).unwrap().len(), 2);
        let stride = if wide { 32 } else { 20 };
        let mut cases = Vec::new();
        let mut truncated = valid.clone();
        truncated.truncate(8 + stride);
        cases.push(truncated);
        let mut overlap = valid.clone();
        if wide {
            let first = overlap[16..24].to_vec();
            overlap[16 + stride..24 + stride].copy_from_slice(&first);
        } else {
            let first = overlap[16..20].to_vec();
            overlap[16 + stride..20 + stride].copy_from_slice(&first);
        }
        cases.push(overlap);
        let mut oob = valid.clone();
        oob[16..20].fill(0xff);
        cases.push(oob);
        let mut empty = valid.clone();
        empty[4..8].fill(0);
        cases.push(empty);
        let mut excessive = valid.clone();
        excessive[4..8].copy_from_slice(&17u32.to_be_bytes());
        cases.push(excessive);
        let mut subtype = valid.clone();
        subtype[12..16].copy_from_slice(&1u32.to_be_bytes());
        cases.push(subtype);
        let mut alignment = valid.clone();
        let at = 8 + if wide { 24 } else { 16 };
        alignment[at..at + 4].copy_from_slice(&64u32.to_be_bytes());
        cases.push(alignment);
        if wide {
            let mut reserved = valid.clone();
            reserved[36..40].copy_from_slice(&1u32.to_be_bytes());
            cases.push(reserved);
        }
        for bytes in cases {
            assert!(macho(&bytes).is_err(), "wide={wide}");
        }
    }
}
#[test]
fn unsigned_adhoc_and_forbidden_entitlements_never_qualify_as_production_images() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("synthetic.c");
    let binary = root.path().join("synthetic");
    std::fs::write(&source, b"int main(void) { return 0; }\n").unwrap();
    assert!(
        std::process::Command::new("/usr/bin/clang")
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        std::process::Command::new("/usr/bin/codesign")
            .arg("--remove-signature")
            .arg(&binary)
            .status()
            .unwrap()
            .success()
    );
    assert!(signature(&binary).is_err());
    for forbidden in [
        None,
        Some("com.apple.security.get-task-allow"),
        Some("com.apple.security.cs.disable-library-validation"),
        Some("com.apple.security.cs.allow-dyld-environment-variables"),
        Some("com.apple.security.cs.allow-jit"),
        Some("com.apple.security.cs.allow-unsigned-executable-memory"),
        Some("com.apple.security.cs.disable-executable-page-protection"),
    ] {
        let mut sign = std::process::Command::new("/usr/bin/codesign");
        sign.args(["--force", "--sign", "-", "--options", "runtime"]);
        let entitlements = root.path().join("entitlements.plist");
        if let Some(key) = forbidden {
            std::fs::write(&entitlements,format!("<?xml version=\"1.0\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>{key}</key><true/></dict></plist>")).unwrap();
            sign.arg("--entitlements").arg(&entitlements);
        }
        sign.arg(&binary);
        assert!(sign.status().unwrap().success());
        assert!(
            signature(&binary).is_err(),
            "ad-hoc is never production trust"
        );
        let url = CFURL::from_path(&binary, false).unwrap();
        let code = SecStaticCode::from_path(&url, Flags::NONE).unwrap();
        assert_eq!(
            signature_policy(&code).is_err(),
            forbidden.is_some(),
            "{forbidden:?}"
        );
    }
}
