//! The internal **candidate key** — content-only candidate identity for dedup and
//! poison (P3 §0.2; `admission-funnel` spec §2 step 1).
//!
//! This is **not** [`crate::canonical`]'s target-mirroring `CallKey`/vouch. That key
//! must agree byte-for-byte with Storm Gate over one concrete wire call; this key is
//! smash-internal, identifies a *candidate* (technique + validated params), and is
//! matched against nothing external. The loop calls it `CanonicalKey`:
//! "`f(declarative candidate content)` only — epoch- and run-independent." Dedup and
//! poison bind to it; the findings ledger's durable cross-run dedup uses the same
//! identity. The two keys must never be conflated, so this lives in its own module.
//!
//! **Why `admit` must recompute it (never trust the proposal's supplied key).** An
//! untrusted generator supplies a candidate with a precomputed key. If admission
//! trusted it, a generator could make two *different* candidates share one key (hiding
//! one behind the other's reservation or poison) or split *one* candidate across two
//! keys (defeating dedup). So admission recomputes the key from the **validated**
//! content and uses the recomputed value — this function is that recompute (spec §2.1).
//!
//! **Content identity, not execution identity.** The key covers technique identity +
//! validated params only — the content-only *finding* identity (§2). Environment,
//! target, and oracle binding are *execution* identity; for this increment they are
//! frozen per run (one environment per run), so they are deliberately **not** folded
//! in here. Widening the execution identity to carry context so distinct contexts
//! don't collapse into one execution is a later addition (§2), not this key's job.
//!
//! **Canonical form.** Reuses [`crate::canonical::canonical_json`] as a proven,
//! deterministic canonical-JSON form, then SHA-256. The reuse is *convenience, not an
//! external contract*: this key is matched against no target. If the canonical rules
//! ever change to track a target, bump [`CANDIDATE_KEY_VERSION`] — the version prefix
//! makes that migration explicit rather than a silent identity shift.

use crate::canonical::canonical_json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Candidate-key rule version. Bump on any change to the canonical content shape or to
/// the reused canonical-JSON rules, so historical keys never silently change identity.
pub const CANDIDATE_KEY_VERSION: u32 = 1;

fn sha256_hex(s: &str) -> String {
    let out = Sha256::digest(s.as_bytes());
    out.iter().map(|b| format!("{b:02x}")).collect()
}

/// The canonical content document the key digests: technique identity + validated
/// params as three distinct JSON fields. Because they are separate fields (not
/// concatenated strings), a different fighter, technique, or param set can never alias
/// another, and a param literally named `fighter`/`technique` sits under `params` and
/// cannot collide with the top-level identity — JSON structure supplies the injectivity.
fn content(fighter: &str, technique: &str, params: &Value) -> Value {
    json!({
        "fighter": fighter,
        "technique": technique,
        "params": params,
    })
}

/// Mint the content-only candidate key from **validated** inputs.
///
/// `fighter` / `technique` are the technique handle's identity strings; `params` is the
/// validated parameter map lowered to a [`serde_json::Value`] (the loop performs that
/// lowering at admit time — it sees `smash_generator::candidate::ParamValue`, which
/// this crate cannot name). The result is deterministic, epoch- and run-independent,
/// and order-independent over param object keys.
///
/// Format: `candidate:v<VERSION>:<sha256_hex(canonical_json(content))>`.
pub fn candidate_key(fighter: &str, technique: &str, params: &Value) -> String {
    let doc = content(fighter, technique, params);
    format!(
        "candidate:v{}:{}",
        CANDIDATE_KEY_VERSION,
        sha256_hex(&canonical_json(&doc))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn deterministic_for_identical_inputs() {
        let p = json!({"recipient": "landlord", "amount": "100"});
        assert_eq!(
            candidate_key("taint-launder", "encoding-equiv", &p),
            candidate_key("taint-launder", "encoding-equiv", &p),
        );
    }

    #[test]
    fn param_key_order_does_not_change_the_key() {
        // canonical_json sorts object keys recursively — the key is content, not spelling.
        let a = json!({"amount": "100", "recipient": "landlord"});
        let b = json!({"recipient": "landlord", "amount": "100"});
        assert_eq!(candidate_key("f", "t", &a), candidate_key("f", "t", &b),);
    }

    #[test]
    fn different_fighter_changes_the_key() {
        let p = json!({"x": 1});
        assert_ne!(candidate_key("f1", "t", &p), candidate_key("f2", "t", &p));
    }

    #[test]
    fn different_technique_changes_the_key() {
        let p = json!({"x": 1});
        assert_ne!(candidate_key("f", "t1", &p), candidate_key("f", "t2", &p));
    }

    #[test]
    fn different_params_change_the_key() {
        assert_ne!(
            candidate_key("f", "t", &json!({"x": 1})),
            candidate_key("f", "t", &json!({"x": 2})),
        );
    }

    #[test]
    fn identity_fields_do_not_alias_across_the_boundary() {
        // fighter="ab",technique="c" must not collide with fighter="a",technique="bc".
        let p = json!({});
        assert_ne!(candidate_key("ab", "c", &p), candidate_key("a", "bc", &p),);
    }

    #[test]
    fn a_param_named_fighter_does_not_collide_with_identity() {
        // A param key colliding by name with a top-level identity field is isolated
        // under `params`, so it cannot forge a different candidate's identity.
        let forged = candidate_key("real", "t", &json!({"fighter": "spoof"}));
        let other = candidate_key("spoof", "t", &json!({}));
        assert_ne!(forged, other);
    }

    #[test]
    fn format_is_versioned_and_hex() {
        let k = candidate_key("f", "t", &json!({"x": 1}));
        let prefix = format!("candidate:v{CANDIDATE_KEY_VERSION}:");
        assert!(
            k.starts_with(&prefix),
            "key must carry the version prefix: {k}"
        );
        let hex = &k[prefix.len()..];
        assert_eq!(hex.len(), 64, "sha-256 hex is 64 chars");
        assert!(hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    #[test]
    fn version_is_v1() {
        assert_eq!(CANDIDATE_KEY_VERSION, 1);
    }
}
