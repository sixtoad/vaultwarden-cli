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
/// Boundaries and isolated header faults added by the #49 native mutation campaign.
#[test]
fn native_image_size_slice_count_and_alignment_boundaries_are_inclusive() {
    let valid = thin(&signed_commands());
    let mut largest = valid.clone();
    largest.resize(64 * 1024 * 1024, 0);
    assert!(macho(&largest).is_ok(), "exactly 64 MiB is permitted");
    largest.push(0);
    assert!(macho(&largest).is_err());
    let sixteen = fat(&vec![valid.clone(); 16], false);
    assert_eq!(macho(&sixteen).unwrap().len(), 16);
    // 2^3 alignment: the first slice starts at 8 + 20 = 28 bytes, which is not a
    // multiple of 8; move it to 32 (aligned) and declare the alignment.
    let mut aligned = vec![0u8; 32];
    aligned[..4].copy_from_slice(&0xcafebabeu32.to_be_bytes());
    aligned[4..8].copy_from_slice(&1u32.to_be_bytes());
    aligned[8..12].copy_from_slice(&0x0100000cu32.to_be_bytes());
    aligned[16..20].copy_from_slice(&32u32.to_be_bytes());
    aligned[20..24].copy_from_slice(&(valid.len() as u32).to_be_bytes());
    aligned[24..28].copy_from_slice(&3u32.to_be_bytes());
    aligned.extend_from_slice(&valid);
    assert_eq!(macho(&aligned).unwrap(), vec![32]);
    let mut misaligned = aligned.clone();
    misaligned[24..28].copy_from_slice(&6u32.to_be_bytes());
    assert!(macho(&misaligned).is_err(), "32 is not 64-aligned");
    let mut foreign = fat(std::slice::from_ref(&valid), false);
    foreign[8..12].copy_from_slice(&0x01000007u32.to_be_bytes());
    assert!(macho(&foreign).is_err(), "no arm64 slice");
}
#[test]
fn native_image_header_fields_are_each_required() {
    let valid = thin(&signed_commands());
    for (label, offset, value) in [
        ("x86_64 cpu type", 4, 0x01000007),
        ("dylib file type", 12, 6),
        ("zero commands", 16, 0),
    ] {
        let mut bytes = valid.clone();
        put(&mut bytes, offset, value);
        assert!(macho(&bytes).is_err(), "{label}");
    }
    let mut slice = valid.clone();
    put(&mut slice, 0, 0xfeedface);
    assert!(macho(&fat(&[slice], false)).is_err(), "32-bit slice magic");
}
#[test]
fn native_loader_command_bounds_are_inclusive_and_isolated() {
    let mut commands = signed_commands();
    // Recognized 8-byte metadata command (minimum size) and the 4096-command limit.
    let mut minimal = vec![0; 8];
    put(&mut minimal, 0, 0x2a);
    put(&mut minimal, 4, 8);
    commands.push(minimal.clone());
    assert!(macho(&thin(&commands)).is_ok(), "8-byte command");
    let mut many = signed_commands();
    many.extend(std::iter::repeat_n(minimal.clone(), 4094));
    assert!(macho(&thin(&many)).is_ok(), "4096 commands");
    many.push(minimal);
    assert!(macho(&thin(&many)).is_err(), "4097 commands");
    // Names may start after padding beyond the fixed command fields.
    let mut padded = signed_commands();
    padded[0] = command(0xe, 16, b"/usr/lib/dyld");
    padded.push(command(0xc, 32, b"/usr/lib/libSystem.B.dylib"));
    assert!(
        macho(&thin(&padded)).is_ok(),
        "padded loader and dylib names"
    );
    let mut cases: Vec<(&str, Vec<Vec<u8>>)> = Vec::new();
    let mut private = signed_commands();
    private.push(command(
        0xc,
        24,
        b"/System/Library/PrivateFrameworks/CoreSymbolication.framework/Versions/A/CoreSymbolication",
    ));
    cases.push(("shared-cache private framework", private));
    let mut wide = signed_commands();
    wide[1] = vec![0; 24];
    put(&mut wide[1], 0, 0x1d);
    put(&mut wide[1], 4, 24);
    put(&mut wide[1], 12, 16);
    cases.push(("24-byte signature command", wide));
    let mut empty = signed_commands();
    put(&mut empty[1], 12, 0);
    cases.push(("empty signature", empty));
    for (label, commands) in cases {
        assert!(macho(&thin(&commands)).is_err(), "{label}");
    }
}
/// Fat-header and load-command edges that the CI generated run left alive (#49).
#[test]
fn native_fat_table_limits_header_overlap_and_adjacent_out_of_order_slices() {
    let valid = thin(&signed_commands());
    let length = valid.len();
    // Seventeen well-formed arm64 slices exceed the 16-slice limit on their own.
    assert!(macho(&fat(&vec![valid.clone(); 17], false)).is_err());
    // A non-native slice may not lie inside the fat table (here inside its own entry).
    let mut inside = fat(&[valid.clone(), valid.clone()], false);
    inside[28..32].copy_from_slice(&0x01000007u32.to_be_bytes());
    inside[36..40].copy_from_slice(&32u32.to_be_bytes());
    inside[40..44].copy_from_slice(&8u32.to_be_bytes());
    assert!(macho(&inside).is_err(), "slice inside the fat table");
    // Slices listed out of file order may be adjacent: touching is not overlapping.
    let mut swapped = fat(&[valid.clone(), valid], false);
    let (first, second) = (48u32, (48 + length) as u32);
    swapped[16..20].copy_from_slice(&second.to_be_bytes());
    swapped[36..40].copy_from_slice(&first.to_be_bytes());
    assert_eq!(macho(&swapped).unwrap(), vec![48 + length, 48]);
}
#[test]
fn native_load_commands_must_fit_the_file_and_have_their_minimum_shape() {
    let valid = signed_commands();
    // Commands claimed past the end of the file are rejected before any is read.
    let mut beyond = vec![command(0xc, 24, b"/usr/lib/libSystem.B.dylib")];
    beyond.extend(valid.iter().cloned());
    let mut bytes = thin(&beyond);
    put(&mut bytes, 36, 4096);
    put(
        &mut bytes,
        20,
        (4096 + valid[0].len() + valid[1].len()) as u32,
    );
    assert!(macho(&bytes).is_err(), "commands beyond the file");
    // A zero-size command (here the last one, read from the signature data) never
    // advances and is rejected even when every other count would balance.
    let mut zero = thin(&valid);
    let end = 32 + valid[0].len() + valid[1].len();
    put(&mut zero, 16, 3);
    put(&mut zero, end, 0x2a);
    put(&mut zero, end + 4, 0);
    assert!(macho(&zero).is_err(), "zero-size command");
    // A dylib name may not start inside the fixed dylib command fields.
    let mut dylib = valid.clone();
    dylib.push(command(0xc, 16, b"/usr/lib/libSystem.B.dylib"));
    assert!(
        macho(&thin(&dylib)).is_err(),
        "dylib name inside its fields"
    );
}
#[test]
fn native_signature_policy_requires_the_hardened_runtime() {
    let root = tempfile::tempdir().unwrap();
    // The policy requires the hardened runtime flag, not only acceptable entitlements.
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
    for (options, runtime) in [(None, false), (Some("runtime"), true)] {
        let mut sign = std::process::Command::new("/usr/bin/codesign");
        sign.args(["--force", "--sign", "-"]);
        if let Some(options) = options {
            sign.args(["--options", options]);
        }
        assert!(sign.arg(&binary).status().unwrap().success());
        let url = CFURL::from_path(&binary, false).unwrap();
        let code = SecStaticCode::from_path(&url, Flags::NONE).unwrap();
        assert_eq!(signature_policy(&code).is_ok(), runtime, "{options:?}");
    }
}

/// A release-signed (Developer ID Application, team `RELEASE_TEAM_ID`, hardened
/// runtime) thin arm64 binary supplied by the publisher; CI has no signing identity.
/// `docs/desktop-installation.md` gives the commands that produce it.
fn release_fixture() -> std::path::PathBuf {
    std::env::var_os("VW_RELEASE_SIGNED_FIXTURE")
        .map(std::path::PathBuf::from)
        .expect("VW_RELEASE_SIGNED_FIXTURE names a release-signed arm64 binary")
}
#[test]
#[ignore = "needs a release-signed fixture: VW_RELEASE_SIGNED_FIXTURE"]
fn one_image_never_mixes_publishers_across_native_slices() {
    let root = tempfile::tempdir().unwrap();
    let apple = root.path().join("apple-arm64e");
    let mixed = root.path().join("mixed");
    let lipo = |args: &[&std::ffi::OsStr]| {
        assert!(
            std::process::Command::new("/usr/bin/lipo")
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    };
    lipo(&[
        "/usr/bin/ssh".as_ref(),
        "-thin".as_ref(),
        "arm64e".as_ref(),
        "-output".as_ref(),
        apple.as_os_str(),
    ]);
    let release = release_fixture();
    assert!(signature(&apple).is_ok(), "an Apple slice alone is trusted");
    assert!(
        signature(&release).is_ok(),
        "a release slice alone is trusted"
    );
    lipo(&[
        "-create".as_ref(),
        apple.as_os_str(),
        release.as_os_str(),
        "-output".as_ref(),
        mixed.as_os_str(),
    ]);
    assert_eq!(macho(&std::fs::read(&mixed).unwrap()).unwrap().len(), 2);
    assert!(
        signature(&mixed).is_err(),
        "slices of different publishers are one image only in name"
    );
}
fn static_code(path: &std::path::Path) -> SecStaticCode {
    let url = CFURL::from_path(path, false).unwrap();
    SecStaticCode::from_path(&url, Flags::NONE).unwrap()
}
#[test]
fn release_requirement_is_the_full_developer_id_chain_of_the_release_team() {
    assert_eq!(RELEASE_TEAM_ID, "9884BZY594");
    assert_eq!(
        release_requirement(),
        "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and \
         certificate leaf[field.1.2.840.113635.100.6.1.13] exists and \
         certificate leaf[subject.OU] = \"9884BZY594\""
    );
    // Image trust is Apple or a Developer ID chain with the Developer ID intermediate.
    assert_eq!(
        trusted_requirement(),
        format!("anchor apple or ({DEVELOPER_ID})")
    );
    assert!(DEVELOPER_ID.contains("certificate 1[field.1.2.840.113635.100.6.2.6] exists"));
    for requirement in [trusted_requirement(), release_requirement()] {
        assert!(
            requirement.parse::<SecRequirement>().is_ok(),
            "{requirement}"
        );
    }
}
#[test]
fn apple_system_image_is_trusted_but_never_the_release_publisher() {
    let ssh = std::path::Path::new("/usr/bin/ssh");
    assert!(signature(ssh).is_ok());
    let code = static_code(ssh);
    assert_eq!(publisher(&code).unwrap(), Publisher::Apple);
    assert!(!satisfies(&code, &release_requirement()).unwrap());
}
#[test]
fn development_signed_build_is_not_trusted_as_the_release_build() {
    // The development bundle signs its commands ad hoc with a hardened runtime.
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("development.c");
    let binary = root.path().join("vaultwarden-accessd");
    std::fs::write(&source, b"int main(void) { return 0; }\n").unwrap();
    assert!(
        std::process::Command::new("/usr/bin/clang")
            .args(["-arch", "arm64"])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        std::process::Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--options", "runtime"])
            .args(["--identifier", "dev.vaultwarden.vaultwarden-accessd"])
            .arg(&binary)
            .status()
            .unwrap()
            .success()
    );
    let code = static_code(&binary);
    assert!(!satisfies(&code, &release_requirement()).unwrap());
    assert!(!satisfies(&code, &trusted_requirement()).unwrap());
    assert!(publisher(&code).is_err());
    assert!(signature(&binary).is_err());
}
#[test]
#[ignore = "needs a release-signed fixture: VW_RELEASE_SIGNED_FIXTURE"]
fn release_signed_build_is_trusted_as_release_and_not_as_anything_else() {
    let release = release_fixture();
    let requirement = signature(&release).unwrap();
    assert!(requirement.starts_with("(cdhash H\""), "{requirement}");
    let code = static_code(&release);
    assert_eq!(publisher(&code).unwrap(), Publisher::Release);
    assert!(satisfies(&code, &release_requirement()).unwrap());
    assert!(!satisfies(&code, "anchor apple").unwrap());
    assert_eq!(team_identifier(&code).unwrap(), RELEASE_TEAM_ID);
    // Another team's requirement never admits the release build.
    assert!(
        !satisfies(
            &code,
            &release_requirement().replace(RELEASE_TEAM_ID, "ABCDE12345")
        )
        .unwrap()
    );
}
