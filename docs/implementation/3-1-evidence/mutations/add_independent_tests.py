from pathlib import Path
import sys
r=Path(sys.argv[1]);p=r/'src/access/policy.rs';s=p.read_text()
needle='    #[test]\n    fn ssh_normalization_revision_review_and_persistence()'
new='''    #[test]
    fn ssh_revision_projection_matches_explicit_v3_contract() {
        // Independent golden projection uses stable symbolic executable paths,
        // so omitting a constant field (SSH use or execution profile) is visible.
        let image = ResolvedImage {
            image_id: "deploy-image".into(),
            execution_root: "/opt/vw-access".into(),
            path: "/opt/vw-access/deploy".into(),
            sha256: "a".repeat(64),
            profile: ExecutionProfile::ReviewedSelfContainedElf64V1,
        };
        assert_eq!(revision_for(&test_ssh_draft(), &image),
            "a97fb6ff3bca64fb5339c76464e8b8b7da88e6022f7cac90598310d647e5e065");
    }
'''
assert s.count(needle)==1;s=s.replace(needle,new+needle)
needle='        assert_eq!(review.ssh, Some(draft.ssh.as_ref().unwrap().review()));'
# Rustfmt may split the original assertion.
if needle not in s:
 needle='''        assert_eq!(
            review.ssh,
            Some(draft.ssh.as_ref().unwrap().review())
        );'''
if needle not in s:
 a=s.index('        assert_eq!(review.ssh');print(s[a:a+180]);raise AssertionError('review expected assertion')
new='''        assert_eq!(review.ssh, Some(SshReview {
            working_directory: "/var/empty".into(),
            destination: SshDestination {
                host: "backup.example.test".into(), port: 2222, user: "backup".into(),
                resource_path: "/srv/archive".into(), host_fingerprint: format!("SHA256:{}", "A".repeat(43)),
            },
        }));'''
s=s.replace(needle,new)
needle='''            ("/targets", serde_json::json!(["generic"])),'''
assert s.count(needle)==1;s=s.replace(needle,'''            // Change only the algorithm prefix; keep valid base64 for 32 bytes.
            ("/ssh/destination/host_fingerprint", serde_json::json!(format!("MD5:{}", "A".repeat(43)))),
            // Change only one base64 character; preserve the encoded length.
            ("/ssh/destination/host_fingerprint", serde_json::json!(format!("SHA256:?{}", "A".repeat(42)))),
            // Valid SHA256/base64 envelope, one byte below/above the digest size.
            ("/ssh/destination/host_fingerprint", serde_json::json!(format!("SHA256:{}", STANDARD_NO_PAD.encode([0;31])))),
            ("/ssh/destination/host_fingerprint", serde_json::json!(format!("SHA256:{}", STANDARD_NO_PAD.encode([0;33])))),
'''+needle)
needle='''            ("", "command"),'''
assert s.count(needle)==1;s=s.replace(needle,'''            ("", "remote"), ("", "host"), ("", "key_path"), ("", "options"), ("", "working_directory"),
            ("/ssh", "remote"), ("/ssh", "host"),
            ("/ssh/destination", "command"), ("/ssh/destination", "key_path"), ("/ssh/destination", "options"), ("/ssh/destination", "working_directory"),
'''+needle)
p.write_text(s)
p=r/'src/access/ports.rs';s=p.read_text();needle='''    #[test]
    fn child_environment_is_explicit_redacted_and_rejects_unsafe_mappings()'''
new='''    #[test]
    fn ssh_verifier_default_denies_eligibility() {
        struct Unsupported;
        impl LoginEligibilityVerifier for Unsupported {
            fn is_login_eligible(&self, _: &str, _: &[LoginField], _: &str) -> Result<bool, LoginEligibilityError> {
                panic!("SSH eligibility must not fall through to login eligibility")
            }
        }
        assert_eq!(Unsupported.is_ssh_eligible("11111111-1111-1111-1111-111111111111"), Ok(false));
    }
'''
assert s.count(needle)==1;s=s.replace(needle,new+needle);p.write_text(s)
p=r/'src/adapters/vaultwarden.rs';s=p.read_text();needle='''        for (old, new) in [
            ("\\\"type\\\":5", "\\\"type\\\":5,\\\"Type\\\":5"),'''
new='''        for (old, new) in [
            ("\\\"type\\\":5", "\\\"type\\\":5,\\\"type\\\":5"),
            ("\\\"privateKey\\\":\\\"private-key-sentinel\\\"", "\\\"privateKey\\\":\\\"private-key-sentinel\\\",\\\"privateKey\\\":\\\"other\\\""),
            ("\\\"type\\\":5", "\\\"type\\\":5,\\\"Type\\\":5"),'''
assert s.count(needle)==1;s=s.replace(needle,new);p.write_text(s)
p=r/'src/adapters/vaultwarden.rs';s=p.read_text();needle='''        let encoded = serde_json::to_string(&baseline).unwrap();
'''
new=needle+'''        // Repeated identical spelling must be rejected before a Value could
        // collapse it, even when both copies carry the same eligible value.
        for (container, field) in [("", "id"), ("", "type"), ("", "deletedDate"), ("", "sshKey"),
            ("sshKey", "privateKey"), ("sshKey", "publicKey"), ("sshKey", "keyFingerprint")] {
            let object = if container.is_empty() { &baseline } else { &baseline[container] };
            let member = format!("{}:{}", serde_json::to_string(field).unwrap(), serde_json::to_string(&object[field]).unwrap());
            let duplicate = encoded.replacen(&member, &format!("{member},{member}"), 1);
            assert_ne!(duplicate, encoded, "fixture replacement {field}");
            assert_eq!(eligible_ssh_metadata(duplicate.as_bytes(), ITEM), Err(SessionError::BackendUnavailable), "duplicate {field}");
        }
'''
assert s.count(needle)==1;s=s.replace(needle,new);p.write_text(s)
p=r/'tests/ui/direct-request.mjs';s=p.read_text();needle="['Backup SSH','ssh','backup.example.test'";assert s.count(needle)==1;s=s.replace(needle,"['Backup SSH (ssh)','backup.example.test'");p.write_text(s)
