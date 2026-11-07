//! Canonical JSON and the argument digest — the byte-identity boundary.
//!
//! This is the most correctness-critical module in the engine. The replay
//! contract binds a probe to a real effect through a key of the form
//! `power_move:<tool>:<sha256_hex(canonical_json(arguments))>`, and the target
//! gate (Storm Gate) signs its vouch over the *same* key. If this crate's
//! `canonical_json` diverges from the target's by a single byte, the digest
//! diverges, the key diverges, and the correlation silently fails — a probe
//! would look un-vouched even when the gate approved it, or vice versa.
//!
//! So this is a **reference canonicalizer**: its whole job is to *agree*,
//! byte-for-byte, with the target. It is a faithful mirror of Storm Gate's
//! `canonical_json` (realfield-core), not an independent reimplementation, and
//! it uses the same library (`serde_json`) the producer uses so that number
//! formatting and string escaping match by construction rather than by guess.
//!
//! > A reference canonicalizer that mirrors the target can only ever *confirm*
//! > what the target already does. Finding where a target's canonicalizer
//! > *diverges* from semantic intent (a canonicalization-collision bypass) is a
//! > separate, independent fighter — see `design/discovery-and-coverage.md`.
//! > Do not conflate the two: this module must agree; that fighter must not.
//!
//! ## The v1/v2 rule set (mirrored from the source)
//!
//! - Object keys are sorted recursively by byte order; array order is preserved
//!   (order is semantic in arrays). Compact serialization; scalars via
//!   `serde_json`. **No string-content normalisation**: `"ls -la"` and
//!   `"ls  -la"` are different canonical values — any normalisation widens what
//!   one approval covers, so per-tool normalisers are separate layered modules,
//!   never folded in here.
//! - **Duplicate object keys are rejected** at the parse boundary
//!   ([`parse_no_duplicates`]), because `serde_json` otherwise collapses
//!   duplicates (last-wins) before a `Value` is ever canonicalized. That
//!   collapse is the canonicalization bypass: without rejection, the gate can
//!   hash one key while a differently-parsing backend executes another.
//! - Numbers (v2, the numeric cutover): integers keep their exact digits at any
//!   magnitude; float-shaped numbers normalise through `f64` to the shortest
//!   round-trip form, so `1e2`, `100.0`, and `1.00e2` are one canonical value.
//!
//! The vectors in the tests are lifted from Storm Gate's own `canonical_json.rs`
//! test suite; they are the cross-implementation contract this module must hold.

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use smash_core::capability::ArgsDigest;
use std::fmt;

/// Canonical JSON version (mirrors the source). v2: integers exact at any
/// magnitude; float-shaped numbers normalise to shortest round-trip `f64`.
pub const CANON_VERSION: u32 = 2;

/// `serde_json`'s `arbitrary_precision` marker: numbers cross `deserialize_any`
/// as a single-entry map keyed by this constant (private to `serde_json`, but
/// wire-stable across 1.0.x; the lockfile pins the version).
const ARBITRARY_NUMBER_KEY: &str = "$serde_json::private::Number";

// ── Errors ──────────────────────────────────────────────────────────────────

/// Why a strict parse was refused. Loggable; maps to a verdict of `Denied`/
/// `Error` upstream, never a silent pass.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CanonError {
    /// An object carried the same key twice — rejected because the collapse
    /// is a canonicalization-bypass primitive.
    DuplicateKey,
    /// The input was not well-formed JSON (malformed, trailing data, empty, or
    /// a crafted non-numeric arbitrary-precision map).
    Json(String),
}

impl fmt::Display for CanonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanonError::DuplicateKey => f.write_str("duplicate object key"),
            CanonError::Json(msg) => write!(f, "invalid JSON: {msg}"),
        }
    }
}

impl std::error::Error for CanonError {}

// ── Canonicalization ──────────────────────────────────────────────────────

/// Canonical JSON serialization with recursively sorted object keys.
///
/// A faithful mirror of Storm Gate's `canonical_json`. With `serde_json`'s
/// `preserve_order` feature the map is insertion-ordered; without it, already
/// sorted — the explicit sort here makes the output identical under either, and
/// identical to the producer.
pub fn canonical_json(value: &Value) -> String {
    fn canon(v: &Value) -> Value {
        match v {
            Value::Object(map) => {
                let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
                sorted.sort_by(|a, b| a.0.cmp(b.0));
                Value::Object(
                    sorted
                        .into_iter()
                        .map(|(k, v)| (k.clone(), canon(v)))
                        .collect(),
                )
            }
            Value::Array(items) => Value::Array(items.iter().map(canon).collect()),
            // v2 number rules: integers keep their exact digits (arbitrary
            // magnitude never collapses to a float); float-shaped numbers
            // normalise through f64 to the shortest round-trip form.
            Value::Number(n) => {
                let raw = n.to_string();
                let float_shaped = raw.bytes().any(|b| matches!(b, b'.' | b'e' | b'E'));
                if float_shaped {
                    match n.as_f64().and_then(serde_json::Number::from_f64) {
                        Some(normalized) => Value::Number(normalized),
                        None => Value::Number(n.clone()),
                    }
                } else {
                    Value::Number(n.clone())
                }
            }
            other => other.clone(),
        }
    }
    serde_json::to_string(&canon(value)).unwrap_or_else(|_| "null".to_string())
}

// ── Strict parse boundary (duplicate-key rejection) ─────────────────────────

/// A `serde_json::Value` parsed with duplicate object keys rejected.
#[derive(Debug, Clone, PartialEq)]
pub struct NoDupValue(pub Value);

impl<'de> Deserialize<'de> for NoDupValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = NoDupValue;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON without duplicate object keys")
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
                Ok(NoDupValue(Value::Bool(v)))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
                Ok(NoDupValue(Value::Number(v.into())))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
                Ok(NoDupValue(Value::Number(v.into())))
            }

            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match serde_json::Number::from_f64(v) {
                    Some(n) => Ok(NoDupValue(Value::Number(n))),
                    None => Err(de::Error::custom("non-finite number is not valid JSON")),
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                Ok(NoDupValue(Value::String(v.to_owned())))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
                Ok(NoDupValue(Value::String(v)))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(NoDupValue(Value::Null))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element::<NoDupValue>()? {
                    items.push(item.0);
                }
                Ok(NoDupValue(Value::Array(items)))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                // serde_json's arbitrary_precision routes every number through
                // visit_map as a single-entry `{ARBITRARY_NUMBER_KEY: "<raw>"}`
                // magic map. Recognize it and round-trip the raw text through
                // Number's own Deserialize — the fail-closed gate: text that is
                // not a valid JSON number is rejected here.
                let Some(first_key) = map.next_key::<String>()? else {
                    return Ok(NoDupValue(Value::Object(serde_json::Map::new())));
                };
                if first_key == ARBITRARY_NUMBER_KEY {
                    let raw: String = map.next_value()?;
                    let number: serde_json::Number = serde_json::from_str(&raw)
                        .map_err(|_| de::Error::custom("malformed number"))?;
                    return Ok(NoDupValue(Value::Number(number)));
                }
                let mut object = serde_json::Map::new();
                let first_value = map.next_value::<NoDupValue>()?;
                if object.insert(first_key, first_value.0).is_some() {
                    return Err(de::Error::custom("duplicate object key"));
                }
                while let Some(key) = map.next_key::<String>()? {
                    let value = map.next_value::<NoDupValue>()?;
                    if object.insert(key, value.0).is_some() {
                        return Err(de::Error::custom("duplicate object key"));
                    }
                }
                Ok(NoDupValue(Value::Object(object)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

/// Parse raw JSON bytes, rejecting any object with duplicate keys.
///
/// This is the parse boundary the digest path must use: plain `serde_json`
/// `Value` parsing collapses duplicate keys (last-wins), which would let the
/// gate hash one key while a differently-parsing harness executes another.
pub fn parse_no_duplicates(bytes: &[u8]) -> Result<Value, CanonError> {
    match serde_json::from_slice::<NoDupValue>(bytes) {
        Ok(v) => Ok(v.0),
        Err(e) => {
            let msg = e.to_string();
            if msg.starts_with("duplicate object key") {
                Err(CanonError::DuplicateKey)
            } else {
                Err(CanonError::Json(msg))
            }
        }
    }
}

/// Parse (duplicate-key-rejecting) and canonicalize in one step — the single
/// entry point for deriving digest input from raw bytes.
pub fn canonical_json_bytes(bytes: &[u8]) -> Result<String, CanonError> {
    parse_no_duplicates(bytes).map(|v| canonical_json(&v))
}

// ── Argument digest and vouch ───────────────────────────────────────────────

/// The core argument digest: `sha256(canonical_json(value))`, as the
/// [`ArgsDigest`] core consumes to build a [`CallKey`].
///
/// [`CallKey`]: smash_core::capability::CallKey
pub fn args_digest(value: &Value) -> ArgsDigest {
    let canon = canonical_json(value);
    let mut hasher = Sha256::new();
    hasher.update(canon.as_bytes());
    let out = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    ArgsDigest(bytes)
}

/// The same digest from raw bytes, through the strict (duplicate-rejecting)
/// parse boundary.
pub fn args_digest_bytes(bytes: &[u8]) -> Result<ArgsDigest, CanonError> {
    let canon = canonical_json_bytes(bytes)?;
    let mut hasher = Sha256::new();
    hasher.update(canon.as_bytes());
    let out = hasher.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    Ok(ArgsDigest(buf))
}

/// Hex of the argument digest — lowercase, 64 chars. Matches core's
/// [`ArgsDigest::to_hex`] and Storm Gate's `hex::encode(sha256(...))`.
pub fn args_hash(value: &Value) -> String {
    args_digest(value).to_hex()
}

/// The argument-bound power-move vouch string, byte-identical to Storm Gate's:
/// `power_move:<tool>:<sha256_hex(canonical_json(arguments))>`.
///
/// This is the string the target gate signs and the key core's
/// [`Call::key`](smash_core::capability::Call::key) emits. Smash uses it to tell
/// whether the gate vouched for *this exact call*, and to build a core `Call`
/// whose `args_digest` produces the same key.
pub fn power_move_vouch(tool: &str, value: &Value) -> String {
    format!("power_move:{}:{}", tool, args_hash(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use smash_core::capability::{Authority, Call, Target};

    // ── Vectors lifted from Storm Gate's canonical_json.rs ───────────────
    // These are the cross-implementation contract: byte-identity with the
    // producer is proven here, not assumed.

    #[test]
    fn sorts_keys_recursively_and_preserves_array_order() {
        let v = json!({"b": [{"z": 2, "a": 1}, 3], "a": 0});
        assert_eq!(canonical_json(&v), r#"{"a":0,"b":[{"a":1,"z":2},3]}"#);
    }

    #[test]
    fn empty_containers_are_compact() {
        assert_eq!(canonical_json(&json!({})), "{}");
        assert_eq!(canonical_json(&json!([])), "[]");
        assert_eq!(
            canonical_json(&json!({"a": {}, "b": []})),
            r#"{"a":{},"b":[]}"#
        );
    }

    #[test]
    fn escapes_strings_via_serde_json() {
        let v = json!({"s": "a\"b\\c\nd"});
        assert_eq!(canonical_json(&v), r#"{"s":"a\"b\\c\nd"}"#);
    }

    #[test]
    fn key_order_invariant() {
        let a = json!({"x": 1, "a": 2});
        let b = json!({"a": 2, "x": 1});
        assert_eq!(canonical_json(&a), canonical_json(&b));
    }

    #[test]
    fn gate_v6_4_recursive_sort_vector() {
        // From gate.rs V6.4: nested sort, compact.
        let a = json!({"b": {"z": 1, "a": 2}, "a": [{"y": 1, "x": 2}]});
        assert_eq!(
            canonical_json(&a),
            r#"{"a":[{"x":2,"y":1}],"b":{"a":2,"z":1}}"#
        );
    }

    #[test]
    fn does_not_normalise_string_content() {
        // Whitespace INSIDE a string value is content, not formatting.
        let a = json!({"command": "ls -la"});
        let b = json!({"command": "ls  -la"});
        assert_ne!(canonical_json(&a), canonical_json(&b));
        assert_ne!(args_hash(&a), args_hash(&b));
    }

    // ── Strict parse boundary ────────────────────────────────────────────

    #[test]
    fn parse_rejects_duplicate_keys() {
        assert_eq!(
            parse_no_duplicates(br#"{"a":1,"a":2}"#).unwrap_err(),
            CanonError::DuplicateKey
        );
    }

    #[test]
    fn parse_rejects_duplicate_keys_at_any_depth() {
        assert_eq!(
            parse_no_duplicates(br#"{"x":{"a":1,"a":2}}"#).unwrap_err(),
            CanonError::DuplicateKey
        );
        assert_eq!(
            parse_no_duplicates(br#"[{"a":1,"a":2}]"#).unwrap_err(),
            CanonError::DuplicateKey
        );
        assert_eq!(
            parse_no_duplicates(br#"{"a":1,"b":{"c":1,"c":2}}"#).unwrap_err(),
            CanonError::DuplicateKey
        );
    }

    #[test]
    fn parse_rejects_garbage_trailing_data_and_empty() {
        assert!(matches!(
            parse_no_duplicates(b"not json"),
            Err(CanonError::Json(_))
        ));
        assert!(matches!(
            parse_no_duplicates(b"{} trailing"),
            Err(CanonError::Json(_))
        ));
        assert!(matches!(parse_no_duplicates(b""), Err(CanonError::Json(_))));
    }

    #[test]
    fn parse_accepts_unique_keys_and_matches_plain_parse() {
        let bytes = br#"{"b":1,"a":[2,{"z":3}]}"#;
        let parsed = parse_no_duplicates(bytes).expect("unique keys parse");
        let plain: Value = serde_json::from_slice(bytes).expect("plain parse");
        assert_eq!(parsed, plain);
        assert_eq!(
            canonical_json_bytes(bytes).expect("canonical"),
            r#"{"a":[2,{"z":3}],"b":1}"#
        );
    }

    // ── v2 numeric semantics ─────────────────────────────────────────────

    #[test]
    fn numeric_semantics_v2_integers_exact_floats_normalized() {
        assert_eq!(
            canonical_json_bytes(b"{\"n\":1}").expect("int"),
            r#"{"n":1}"#
        );
        assert_eq!(
            canonical_json_bytes(b"{\"n\":1.0}").expect("float"),
            r#"{"n":1.0}"#
        );
        assert_eq!(
            canonical_json_bytes(b"{\"n\":1e0}").expect("exp"),
            r#"{"n":1.0}"#
        );
        assert_eq!(
            canonical_json_bytes(b"{\"n\":9007199254740993}").expect("u64"),
            r#"{"n":9007199254740993}"#
        );
        // v2: integers are exact at any magnitude — never collapsed to f64.
        assert_eq!(
            canonical_json_bytes(b"{\"n\":123456789012345678901234567890}").expect("big int"),
            r#"{"n":123456789012345678901234567890}"#
        );
        assert_eq!(
            canonical_json_bytes(b"{\"n\":-987654321098765432109876543210}").expect("neg big int"),
            r#"{"n":-987654321098765432109876543210}"#
        );
        // v2: float spellings normalize through f64.
        for spelling in ["1e2", "1.0e2", "100.0", "1.00e2", "10000e-2"] {
            let input = format!("{{\"n\":{spelling}}}");
            assert_eq!(
                canonical_json_bytes(input.as_bytes()).expect("float spelling"),
                r#"{"n":100.0}"#,
                "spelling {spelling} must normalize"
            );
        }
        assert_eq!(
            canonical_json_bytes(b"{\"n\":0.0500}").expect("trailing zeros"),
            r#"{"n":0.05}"#
        );
    }

    #[test]
    fn arbitrary_precision_magic_map_is_interpreted_as_a_number() {
        let v = parse_no_duplicates(br#"{"$serde_json::private::Number":"7"}"#)
            .expect("magic map parses as a number");
        assert_eq!(v, json!(7));
        assert!(parse_no_duplicates(br#"{"$serde_json::private::Number":"abc"}"#).is_err());
    }

    // ── Digest and vouch, tied to core ───────────────────────────────────

    #[test]
    fn args_hash_is_lowercase_64_hex() {
        let h = args_hash(&json!({"a": 1}));
        assert_eq!(h.len(), 64);
        assert!(h
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    #[test]
    fn vouch_stable_across_key_order() {
        let a = json!({"command": "git status", "cwd": "/srv"});
        let b = json!({"cwd": "/srv", "command": "git status"});
        assert_eq!(
            power_move_vouch("terminal", &a),
            power_move_vouch("terminal", &b),
        );
    }

    #[test]
    fn vouch_changes_with_arguments() {
        let a = json!({"command": "git status"});
        let b = json!({"command": "git push origin main"});
        assert_ne!(
            power_move_vouch("terminal", &a),
            power_move_vouch("terminal", &b),
        );
    }

    #[test]
    fn vouch_matches_core_call_key() {
        // The whole point: the engine's canonicalization + digest, fed into
        // core's Call::key, must reproduce exactly the vouch string Storm Gate
        // signs. This is the seam between engine (bytes) and core (key format).
        let params = json!({"amount": "100", "recipient": "landlord"});
        let vouch = power_move_vouch("send_payment", &params);

        let call = Call {
            session: "s-1".into(),
            tool: "send_payment".into(),
            args_digest: args_digest(&params),
            required: Authority::Mutating,
            target: Target::new("http://127.0.0.1:8019"),
        };
        assert_eq!(call.key().as_str(), vouch);
        assert!(vouch.starts_with("power_move:send_payment:"));
    }

    #[test]
    fn digest_from_bytes_rejects_duplicates_before_hashing() {
        // A duplicate-key input must never reach the hasher — it is refused at
        // the parse boundary, so the gate can't hash one key while the backend
        // executes another.
        assert_eq!(
            args_digest_bytes(br#"{"a":1,"a":2}"#).unwrap_err(),
            CanonError::DuplicateKey
        );
    }

    #[test]
    fn canon_version_is_v2() {
        assert_eq!(CANON_VERSION, 2);
    }
}
