//! Protected update of one existing personal Login item (issue 48 phase 2).
//!
//! The policy pins the server, the immutable item ID, the destination binding
//! and the exact producer schema. It never pins a revision: the revision
//! changes on every update, so a pinned one would make the policy single-use.
//! The provider reads the item when a request is created and binds the
//! revision it saw into the review (`UpdateReview::expected_revision`).
use crate::secret_storage::{Destination, valid_field_name, valid_id};
use serde::{Deserialize, Serialize};

/// The effect line every update review shows.
pub const UPDATE_EFFECT_LINE: &str = "UPDATE personal vault item (no create)";
/// Largest accepted `revisionDate` string, as in the trusted CLI path.
const MAX_REVISION_LEN: usize = 64;

/// Operator-owned target and exact producer schema of a protected update.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateEffect {
    pub server: String,
    pub item_id: String,
    pub destination: Destination,
    pub fields: Vec<String>,
}

/// What the human reviews: the policy's effect plus the revision the provider
/// read when the request was created. Never holds a value.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateReview {
    pub server: String,
    pub item_id: String,
    pub destination: Destination,
    pub fields: Vec<String>,
    pub expected_revision: String,
}

/// Field selectors of an update: `password`, `notes` (alone too, D5) and
/// `custom:NAME`; never the `vw-access` marker; no duplicates; the create
/// cardinality limits.
fn valid_fields(fields: &[String]) -> bool {
    let mut seen = std::collections::HashSet::new();
    !fields.is_empty()
        && fields.len() <= 34
        && fields.iter().filter(|f| f.starts_with("custom:")).count() <= 32
        && fields.iter().all(|f| {
            seen.insert(f.as_str())
                && (matches!(f.as_str(), "password" | "notes")
                    || f.strip_prefix("custom:")
                        .is_some_and(|name| valid_field_name(name) && name != "vw-access"))
        })
}

/// A `revisionDate` as read from the server: non-empty, bounded, printable.
#[must_use]
pub fn valid_revision(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_REVISION_LEN && !value.chars().any(char::is_control)
}

impl UpdateEffect {
    #[must_use]
    pub fn valid(&self) -> bool {
        self.destination.item_name().is_ok()
            && valid_id(&self.item_id)
            && self.server.starts_with("https://")
            && self.server.len() <= 512
            && !self.server.chars().any(char::is_control)
            && valid_fields(&self.fields)
    }
    /// The server with trailing slashes removed, as every comparison uses it.
    #[must_use]
    pub fn server_key(&self) -> &str {
        self.server.trim_end_matches('/')
    }
    /// The selectors in the order `SecretImport::selectors` reports them.
    #[must_use]
    pub fn sorted_fields(&self) -> Vec<String> {
        let mut fields = self.fields.clone();
        fields.sort();
        fields
    }
    #[must_use]
    pub fn review(&self, expected_revision: String) -> UpdateReview {
        UpdateReview {
            server: self.server.clone(),
            item_id: self.item_id.clone(),
            destination: self.destination.clone(),
            fields: self.fields.clone(),
            expected_revision,
        }
    }
}

impl UpdateReview {
    #[must_use]
    pub fn effect(&self) -> UpdateEffect {
        UpdateEffect {
            server: self.server.clone(),
            item_id: self.item_id.clone(),
            destination: self.destination.clone(),
            fields: self.fields.clone(),
        }
    }
    #[must_use]
    pub fn valid(&self) -> bool {
        self.effect().valid() && valid_revision(&self.expected_revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn effect() -> UpdateEffect {
        UpdateEffect {
            server: "https://vault.example".into(),
            item_id: "33333333-3333-3333-3333-333333333333".into(),
            destination: Destination {
                account_id: "11111111-1111-1111-1111-111111111111".into(),
                folder: "homelab/production".into(),
                folder_id: "22222222-2222-2222-2222-222222222222".into(),
                reference: "homelab/production/github/token".into(),
            },
            fields: vec!["password".into(), "custom:api-key".into()],
        }
    }

    #[test]
    fn update_effect_accepts_notes_alone_and_refuses_marker_duplicates_and_bad_ids() {
        assert!(effect().valid());
        let mut notes = effect();
        notes.fields = vec!["notes".into()];
        assert!(notes.valid(), "notes alone is a valid update (D5)");
        for fields in [
            vec![],
            vec!["custom:vw-access".to_owned()],
            vec!["password".to_owned(), "password".to_owned()],
            vec!["username".to_owned()],
            vec!["custom:".to_owned()],
            vec!["custom:bad name".to_owned()],
            (0..33).map(|i| format!("custom:f{i}")).collect(),
        ] {
            let mut bad = effect();
            bad.fields = fields.clone();
            assert!(!bad.valid(), "{fields:?}");
        }
        let mut limit = effect();
        limit.fields = (0..32).map(|i| format!("custom:f{i}")).collect();
        limit.fields.extend(["password".into(), "notes".into()]);
        assert!(limit.valid());
        for (server, item) in [
            (
                "http://vault.example",
                "33333333-3333-3333-3333-333333333333",
            ),
            (
                "https://vault.example\n",
                "33333333-3333-3333-3333-333333333333",
            ),
            (
                "https://vault.example",
                "33333333-3333-3333-3333-33333333333A",
            ),
            ("https://vault.example", "not-an-id"),
        ] {
            let mut bad = effect();
            bad.server = server.into();
            bad.item_id = item.into();
            assert!(!bad.valid(), "{server} {item}");
        }
        let mut outside = effect();
        outside.destination.reference = "elsewhere/token".into();
        assert!(!outside.valid());
    }

    #[test]
    fn update_review_binds_a_printable_bounded_revision() {
        let review = effect().review("2026-11-22T09:30:00.123456Z".into());
        assert!(review.valid());
        assert_eq!(review.effect(), effect());
        for revision in [String::new(), "x".repeat(65), "2026\n".into()] {
            assert!(!effect().review(revision.clone()).valid(), "{revision:?}");
        }
        assert!(effect().review("x".repeat(64)).valid());
        assert_eq!(
            effect().sorted_fields(),
            vec!["custom:api-key".to_owned(), "password".to_owned()]
        );
        let mut slash = effect();
        slash.server = "https://vault.example//".into();
        assert_eq!(slash.server_key(), "https://vault.example");
    }
}
