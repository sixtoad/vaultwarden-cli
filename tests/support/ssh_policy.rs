//! Synthetic policy shared only by integration tests.
pub fn draft(image_id: &str) -> vaultwarden_cli::access::policy::OperationPolicyDraft {
    serde_json::from_value(serde_json::json!({
        "id":"ssh-backup", "description":"Back up the fixed resource", "image_id":image_id,
        "targets":[], "arguments":[], "credentials":[],
        "ssh": {
            "credential":{"item_id":"11111111-1111-1111-1111-111111111111","label":"Backup SSH","use_type":"ssh"},
            "working_directory":"/var/empty",
            "destination":{"host":"BACKUP.Example.Test.","port":2222,"user":"backup","resource_path":"/srv/archive","host_fingerprint":format!("SHA256:{}=", "A".repeat(43))}
        }
    })).unwrap()
}
