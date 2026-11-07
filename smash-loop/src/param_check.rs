//! Parameter bounds — the §4 stage-2 admission check's value side (loop-side).
//!
//! The engine owns the *declaration* (`smash_engine::bounds::ParamSpec`, the trusted
//! template metadata). This module owns the *check*: does a generator-produced
//! `smash_generator::candidate::ParamValue` satisfy that spec? The check lives here, in
//! `smash-loop`, because the loop is the only crate that sees both the engine registry
//! and the generator's values (`core ← engine ← {generator, loop}`).
//!
//! The contract (admission-funnel spec §1), enforced with **no coercion**:
//! - exact types — a `Str("1")` never satisfies an `Int` slot;
//! - inclusive integer bounds;
//! - string length in **UTF-8 bytes** (a resource bound), and the declared charset;
//! - every declared map key / slot **required**, every **undeclared** key / slot rejected;
//! - maximum nesting depth and total parameter byte-size, enforced **during the walk**
//!   (so an oversized or explosively-nested input is refused as it is decoded, not after).
//!
//! A failure is a `RejectedAtAdmission` coverage fact upstream (never a silent clamp,
//! never a pass).

use smash_engine::bounds::{ParamSpec, ParamSpecSet, MAX_NESTING_DEPTH};
use smash_generator::candidate::ParamValue;
use std::collections::BTreeMap;
use std::fmt;

/// Total parameter byte-budget for one candidate, charged as the value is walked.
/// Strings cost their UTF-8 byte length; scalars a small fixed cost; containers the sum
/// of their children. Exhausting it rejects the candidate (`TooLarge`).
pub const MAX_TOTAL_PARAM_BYTES: usize = 1 << 20; // 1 MiB

/// Why a candidate's params failed the bounds check. `path` locates the offending value
/// (`slot`, `slot[3]`, `slot.key`). Each maps to `AdmissionDenial::ParamOutOfBounds`
/// upstream and a `RejectedAtAdmission` coverage row.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ParamError {
    /// A param slot not declared by the template.
    UndeclaredSlot { slot: String },
    /// A declared slot with no value (all slots are required).
    MissingSlot { slot: String },
    /// Wrong `ParamValue` variant for the slot's spec (no coercion).
    TypeMismatch { path: String, expected: &'static str },
    /// An integer outside its inclusive `[min, max]`.
    OutOfRange { path: String, min: i64, max: i64, got: i64 },
    /// A string with a disallowed character for its charset.
    BadCharset { path: String },
    /// A string longer than `max_len` UTF-8 bytes.
    TooLong { path: String, max: usize, got: usize },
    /// A list longer than its `max_len`.
    TooMany { path: String, max: usize, got: usize },
    /// A map key not declared by the spec.
    UndeclaredKey { path: String, key: String },
    /// A declared map key with no value.
    MissingKey { path: String, key: String },
    /// A string not among an enum spec's choices.
    NotAChoice { path: String },
    /// Nesting beyond `MAX_NESTING_DEPTH`.
    TooDeep { path: String },
    /// Total parameter byte-budget exhausted.
    TooLarge,
}

impl fmt::Display for ParamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParamError::UndeclaredSlot { slot } => write!(f, "undeclared param slot {slot:?}"),
            ParamError::MissingSlot { slot } => write!(f, "missing required param slot {slot:?}"),
            ParamError::TypeMismatch { path, expected } => {
                write!(f, "{path}: expected {expected}")
            }
            ParamError::OutOfRange { path, min, max, got } => {
                write!(f, "{path}: {got} outside [{min}, {max}]")
            }
            ParamError::BadCharset { path } => write!(f, "{path}: disallowed character"),
            ParamError::TooLong { path, max, got } => {
                write!(f, "{path}: {got} bytes exceeds max {max}")
            }
            ParamError::TooMany { path, max, got } => {
                write!(f, "{path}: {got} elements exceeds max {max}")
            }
            ParamError::UndeclaredKey { path, key } => write!(f, "{path}: undeclared key {key:?}"),
            ParamError::MissingKey { path, key } => write!(f, "{path}: missing required key {key:?}"),
            ParamError::NotAChoice { path } => write!(f, "{path}: not an allowed enum choice"),
            ParamError::TooDeep { path } => write!(f, "{path}: nesting exceeds {MAX_NESTING_DEPTH}"),
            ParamError::TooLarge => write!(f, "total parameter size exceeds {MAX_TOTAL_PARAM_BYTES} bytes"),
        }
    }
}

impl std::error::Error for ParamError {}

/// Check a candidate's whole param map against a template's declared spec set:
/// no undeclared slot, every declared slot present and in bounds.
pub fn check_params(
    specs: &ParamSpecSet,
    params: &BTreeMap<String, ParamValue>,
) -> Result<(), ParamError> {
    // Reject undeclared slots first — a candidate cannot smuggle extra params.
    for key in params.keys() {
        if specs.get(key).is_none() {
            return Err(ParamError::UndeclaredSlot { slot: key.clone() });
        }
    }
    let mut budget = MAX_TOTAL_PARAM_BYTES;
    for (slot, spec) in specs.slots() {
        match params.get(slot) {
            None => return Err(ParamError::MissingSlot { slot: slot.clone() }),
            Some(value) => check_value(spec, value, 1, &mut budget, slot)?,
        }
    }
    Ok(())
}

fn spend(budget: &mut usize, n: usize) -> Result<(), ParamError> {
    *budget = budget.checked_sub(n).ok_or(ParamError::TooLarge)?;
    Ok(())
}

fn check_value(
    spec: &ParamSpec,
    value: &ParamValue,
    depth: usize,
    budget: &mut usize,
    path: &str,
) -> Result<(), ParamError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(ParamError::TooDeep { path: path.to_string() });
    }
    match (spec, value) {
        (ParamSpec::Int { min, max }, ParamValue::Int(n)) => {
            spend(budget, 8)?;
            if n < min || n > max {
                return Err(ParamError::OutOfRange {
                    path: path.to_string(),
                    min: *min,
                    max: *max,
                    got: *n,
                });
            }
        }
        (ParamSpec::Str { max_len, charset }, ParamValue::Str(s)) => {
            let bytes = s.len();
            spend(budget, bytes)?;
            if bytes > *max_len {
                return Err(ParamError::TooLong { path: path.to_string(), max: *max_len, got: bytes });
            }
            if !charset.admits(s) {
                return Err(ParamError::BadCharset { path: path.to_string() });
            }
        }
        (ParamSpec::Bool, ParamValue::Bool(_)) => {
            spend(budget, 1)?;
        }
        (ParamSpec::List { max_len, elem }, ParamValue::List(items)) => {
            if items.len() > *max_len {
                return Err(ParamError::TooMany {
                    path: path.to_string(),
                    max: *max_len,
                    got: items.len(),
                });
            }
            for (i, item) in items.iter().enumerate() {
                check_value(elem, item, depth + 1, budget, &format!("{path}[{i}]"))?;
            }
        }
        (ParamSpec::Map { keys }, ParamValue::Map(m)) => {
            // No undeclared key.
            for k in m.keys() {
                if !keys.contains_key(k) {
                    return Err(ParamError::UndeclaredKey { path: path.to_string(), key: k.clone() });
                }
            }
            // Every declared key required and in bounds.
            for (k, sub) in keys {
                match m.get(k) {
                    None => return Err(ParamError::MissingKey { path: path.to_string(), key: k.clone() }),
                    Some(v) => check_value(sub, v, depth + 1, budget, &format!("{path}.{k}"))?,
                }
            }
        }
        (ParamSpec::Enum { choices }, ParamValue::Str(s)) => {
            spend(budget, s.len())?;
            if !choices.iter().any(|c| c == s) {
                return Err(ParamError::NotAChoice { path: path.to_string() });
            }
        }
        // Any other pairing is a type mismatch — exact types, no coercion.
        (spec, _) => {
            return Err(ParamError::TypeMismatch {
                path: path.to_string(),
                expected: spec_kind(spec),
            });
        }
    }
    Ok(())
}

fn spec_kind(spec: &ParamSpec) -> &'static str {
    match spec {
        ParamSpec::Int { .. } => "int",
        ParamSpec::Str { .. } => "string",
        ParamSpec::Bool => "bool",
        ParamSpec::List { .. } => "list",
        ParamSpec::Map { .. } => "map",
        ParamSpec::Enum { .. } => "enum (string choice)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smash_engine::bounds::{Charset, ParamSpec, ParamSpecSet};

    fn specs() -> ParamSpecSet {
        ParamSpecSet::new()
            .with("recipient", ParamSpec::Str { max_len: 32, charset: Charset::Any })
            .with("amount", ParamSpec::Int { min: 0, max: 1000 })
            .with("method", ParamSpec::Enum { choices: vec!["GET".into(), "POST".into()] })
    }

    fn params(items: &[(&str, ParamValue)]) -> BTreeMap<String, ParamValue> {
        items.iter().cloned().map(|(k, v)| (k.to_string(), v)).collect()
    }

    #[test]
    fn in_bounds_params_pass() {
        let p = params(&[
            ("recipient", ParamValue::Str("landlord".into())),
            ("amount", ParamValue::Int(100)),
            ("method", ParamValue::Str("POST".into())),
        ]);
        assert!(check_params(&specs(), &p).is_ok());
    }

    #[test]
    fn undeclared_slot_is_rejected() {
        let p = params(&[
            ("recipient", ParamValue::Str("x".into())),
            ("amount", ParamValue::Int(1)),
            ("method", ParamValue::Str("GET".into())),
            ("sneaky", ParamValue::Bool(true)),
        ]);
        assert_eq!(check_params(&specs(), &p), Err(ParamError::UndeclaredSlot { slot: "sneaky".into() }));
    }

    #[test]
    fn missing_slot_is_rejected() {
        let p = params(&[("recipient", ParamValue::Str("x".into())), ("amount", ParamValue::Int(1))]);
        assert_eq!(check_params(&specs(), &p), Err(ParamError::MissingSlot { slot: "method".into() }));
    }

    #[test]
    fn type_mismatch_is_rejected_no_coercion() {
        // Str "1" must NOT satisfy an Int slot.
        let p = params(&[
            ("recipient", ParamValue::Str("x".into())),
            ("amount", ParamValue::Str("1".into())),
            ("method", ParamValue::Str("GET".into())),
        ]);
        assert_eq!(
            check_params(&specs(), &p),
            Err(ParamError::TypeMismatch { path: "amount".into(), expected: "int" })
        );
    }

    #[test]
    fn int_out_of_range_is_rejected_inclusive() {
        let p = params(&[
            ("recipient", ParamValue::Str("x".into())),
            ("amount", ParamValue::Int(1001)),
            ("method", ParamValue::Str("GET".into())),
        ]);
        assert!(matches!(check_params(&specs(), &p), Err(ParamError::OutOfRange { .. })));
        // Inclusive: 1000 and 0 are fine.
        for n in [0, 1000] {
            let ok = params(&[
                ("recipient", ParamValue::Str("x".into())),
                ("amount", ParamValue::Int(n)),
                ("method", ParamValue::Str("GET".into())),
            ]);
            assert!(check_params(&specs(), &ok).is_ok(), "{n} is in [0,1000]");
        }
    }

    #[test]
    fn string_length_is_utf8_bytes() {
        // "秘密" is 2 chars but 6 UTF-8 bytes.
        let small = ParamSpecSet::new().with("s", ParamSpec::Str { max_len: 4, charset: Charset::Any });
        let p = params(&[("s", ParamValue::Str("秘密".into()))]);
        assert!(matches!(check_params(&small, &p), Err(ParamError::TooLong { got: 6, max: 4, .. })));
    }

    #[test]
    fn charset_is_enforced() {
        let ascii = ParamSpecSet::new().with("s", ParamSpec::Str { max_len: 32, charset: Charset::AsciiAlnum });
        let p = params(&[("s", ParamValue::Str("a-b".into()))]);
        assert_eq!(check_params(&ascii, &p), Err(ParamError::BadCharset { path: "s".into() }));
    }

    #[test]
    fn enum_rejects_non_choice() {
        let p = params(&[
            ("recipient", ParamValue::Str("x".into())),
            ("amount", ParamValue::Int(1)),
            ("method", ParamValue::Str("DELETE".into())),
        ]);
        assert_eq!(check_params(&specs(), &p), Err(ParamError::NotAChoice { path: "method".into() }));
    }

    #[test]
    fn list_length_and_element_bounds() {
        let s = ParamSpecSet::new().with(
            "tags",
            ParamSpec::List { max_len: 2, elem: Box::new(ParamSpec::Int { min: 0, max: 9 }) },
        );
        let too_many = params(&[("tags", ParamValue::List(vec![ParamValue::Int(1), ParamValue::Int(2), ParamValue::Int(3)]))]);
        assert!(matches!(check_params(&s, &too_many), Err(ParamError::TooMany { .. })));
        let bad_elem = params(&[("tags", ParamValue::List(vec![ParamValue::Int(1), ParamValue::Int(42)]))]);
        match check_params(&s, &bad_elem) {
            Err(ParamError::OutOfRange { path, .. }) => assert_eq!(path, "tags[1]"),
            other => panic!("expected OutOfRange at tags[1], got {other:?}"),
        }
    }

    #[test]
    fn map_requires_declared_keys_and_rejects_undeclared() {
        let s = ParamSpecSet::new().with(
            "opts",
            ParamSpec::Map {
                keys: std::collections::BTreeMap::from([("a".to_string(), ParamSpec::Bool)]),
            },
        );
        let undeclared = params(&[("opts", ParamValue::Map(std::collections::BTreeMap::from([
            ("a".to_string(), ParamValue::Bool(true)),
            ("b".to_string(), ParamValue::Bool(false)),
        ])))]);
        match check_params(&s, &undeclared) {
            Err(ParamError::UndeclaredKey { key, .. }) => assert_eq!(key, "b"),
            other => panic!("expected UndeclaredKey b, got {other:?}"),
        }
        let missing = params(&[("opts", ParamValue::Map(std::collections::BTreeMap::new()))]);
        assert!(matches!(check_params(&s, &missing), Err(ParamError::MissingKey { .. })));
    }

    #[test]
    fn total_size_budget_is_enforced() {
        let s = ParamSpecSet::new().with(
            "blob",
            ParamSpec::Str { max_len: MAX_TOTAL_PARAM_BYTES, charset: Charset::Any },
        );
        // A single string larger than the whole budget is rejected as TooLarge
        // (the per-slot max_len would allow it; the total budget does not).
        let huge = "a".repeat(MAX_TOTAL_PARAM_BYTES + 1);
        let p = params(&[("blob", ParamValue::Str(huge))]);
        assert_eq!(check_params(&s, &p), Err(ParamError::TooLarge));
    }
}
