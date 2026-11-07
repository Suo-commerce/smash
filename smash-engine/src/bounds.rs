//! Parameter bounds — the §4 stage-2 admission check's trusted declaration side.
//!
//! A reviewed template declares, per param slot, a [`ParamSpec`]: the bound an
//! admitted candidate's value for that slot must satisfy. Bounds are **trusted
//! template metadata owned by the registry** (admission-funnel spec §1, decision 1):
//! the untrusted generator *fills* slots, the reviewed template *bounds* them, and a
//! candidate can never widen its own bounds.
//!
//! This module owns the **declaration** half — the `ParamSpec` vocabulary, the
//! per-technique [`ParamSpecSet`], the [`ParamSpecRegistry`] keyed by
//! [`TechniqueHandle`], and **registration-time schema validation** (a malformed spec
//! set is rejected when the template is registered, not at candidate time).
//!
//! The **value check** — "does a `smash_generator::candidate::ParamValue` satisfy this
//! spec?" — deliberately lives in `smash-loop`, not here: `ParamValue` is a
//! `smash-generator` type, and only the loop sees both the engine registry and the
//! generator's values. Keeping the type here (engine) and the value-check there (loop)
//! respects the `core ← engine ← {generator, loop}` layering without forcing `ParamSpec`
//! into `smash-core`. (Generator-side in-range *generation* — the one thing that would
//! require this type in core — is a deferred defense-in-depth optimization; admission
//! re-checks regardless.)

use crate::registry::TechniqueHandle;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Global decode/validation ceilings. These bound a spec set's *declared* shape at
/// registration, and (in the loop's value-check) a candidate's *actual* shape during
/// decoding — an oversized or explosively-nested input is refused before it is walked.
pub const MAX_NESTING_DEPTH: usize = 8;
/// A sane upper bound a single `Str`/`List` slot may declare for its length.
pub const MAX_DECLARED_LEN: usize = 1 << 20; // 1 MiB of bytes / 1M elements

/// The character set a `Str` slot admits. Lengths everywhere are in **UTF-8 bytes**
/// (a resource bound), never char counts.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Charset {
    /// Any valid UTF-8.
    Any,
    /// ASCII only (bytes < 0x80).
    Ascii,
    /// ASCII letters and digits.
    AsciiAlnum,
    /// Printable ASCII (0x20..=0x7E).
    AsciiPrintable,
}

impl Charset {
    /// Whether every char of `s` is admitted by this charset.
    pub fn admits(self, s: &str) -> bool {
        match self {
            Charset::Any => true,
            Charset::Ascii => s.is_ascii(),
            Charset::AsciiAlnum => s.chars().all(|c| c.is_ascii_alphanumeric()),
            Charset::AsciiPrintable => s.chars().all(|c| matches!(c, ' '..='~')),
        }
    }
}

/// The bound declared for one param slot. Exact-typed: a value satisfies a spec only if
/// its `ParamValue` variant matches (no coercion — `Str("1")` never satisfies `Int`).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ParamSpec {
    /// An `i64` within `[min, max]` (inclusive).
    Int { min: i64, max: i64 },
    /// A UTF-8 string of at most `max_len` **bytes**, over `charset`.
    Str { max_len: usize, charset: Charset },
    /// A boolean.
    Bool,
    /// A list of at most `max_len` elements, each satisfying `elem`.
    List {
        max_len: usize,
        elem: Box<ParamSpec>,
    },
    /// A map whose keys are exactly `keys` (every key required, no undeclared key),
    /// each value satisfying its key's spec.
    Map { keys: BTreeMap<String, ParamSpec> },
    /// A string drawn from a fixed, non-empty, unique set of `choices`.
    Enum { choices: Vec<String> },
}

impl ParamSpec {
    /// The declared nesting depth of this spec (leaf = 1).
    pub fn depth(&self) -> usize {
        match self {
            ParamSpec::List { elem, .. } => 1 + elem.depth(),
            ParamSpec::Map { keys } => 1 + keys.values().map(ParamSpec::depth).max().unwrap_or(0),
            _ => 1,
        }
    }

    /// Registration-time well-formedness. A malformed spec can never enter the registry,
    /// so a candidate is never checked against an incoherent bound.
    pub fn validate_schema(&self) -> Result<(), SchemaError> {
        self.validate_at_depth(1)
    }

    fn validate_at_depth(&self, depth: usize) -> Result<(), SchemaError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(SchemaError::TooDeep {
                max: MAX_NESTING_DEPTH,
            });
        }
        match self {
            ParamSpec::Int { min, max } => {
                if min > max {
                    return Err(SchemaError::IntRangeInverted {
                        min: *min,
                        max: *max,
                    });
                }
            }
            ParamSpec::Str { max_len, .. } => {
                if *max_len == 0 || *max_len > MAX_DECLARED_LEN {
                    return Err(SchemaError::LenOutOfRange { got: *max_len });
                }
            }
            ParamSpec::Bool => {}
            ParamSpec::List { max_len, elem } => {
                if *max_len > MAX_DECLARED_LEN {
                    return Err(SchemaError::LenOutOfRange { got: *max_len });
                }
                elem.validate_at_depth(depth + 1)?;
            }
            ParamSpec::Map { keys } => {
                if keys.is_empty() {
                    return Err(SchemaError::EmptyMap);
                }
                for spec in keys.values() {
                    spec.validate_at_depth(depth + 1)?;
                }
            }
            ParamSpec::Enum { choices } => {
                if choices.is_empty() {
                    return Err(SchemaError::EmptyEnum);
                }
                let mut seen = std::collections::BTreeSet::new();
                for c in choices {
                    if !seen.insert(c) {
                        return Err(SchemaError::DuplicateEnumChoice { choice: c.clone() });
                    }
                }
            }
        }
        Ok(())
    }
}

/// The declared bounds for one technique's param slots: slot name → spec. Every declared
/// slot is required (optional/default semantics are a deliberate later addition); a
/// candidate with a missing or undeclared slot is rejected at admission (loop-side check).
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ParamSpecSet {
    slots: BTreeMap<String, ParamSpec>,
}

impl ParamSpecSet {
    pub fn new() -> Self {
        ParamSpecSet::default()
    }

    /// Declare a slot. Builder-style; last-writer-wins on a repeated slot name.
    pub fn with(mut self, slot: impl Into<String>, spec: ParamSpec) -> Self {
        self.slots.insert(slot.into(), spec);
        self
    }

    pub fn slots(&self) -> &BTreeMap<String, ParamSpec> {
        &self.slots
    }

    pub fn get(&self, slot: &str) -> Option<&ParamSpec> {
        self.slots.get(slot)
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Registration-time validation of the whole set: every slot's spec is well-formed.
    pub fn validate_schema(&self) -> Result<(), SchemaError> {
        for (slot, spec) in &self.slots {
            spec.validate_schema().map_err(|e| SchemaError::InSlot {
                slot: slot.clone(),
                inner: Box::new(e),
            })?;
        }
        Ok(())
    }
}

/// Why a declared spec set is rejected at registration.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum SchemaError {
    IntRangeInverted {
        min: i64,
        max: i64,
    },
    LenOutOfRange {
        got: usize,
    },
    EmptyMap,
    EmptyEnum,
    DuplicateEnumChoice {
        choice: String,
    },
    TooDeep {
        max: usize,
    },
    InSlot {
        slot: String,
        inner: Box<SchemaError>,
    },
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemaError::IntRangeInverted { min, max } => {
                write!(f, "int range inverted: min {min} > max {max}")
            }
            SchemaError::LenOutOfRange { got } => {
                write!(
                    f,
                    "declared length {got} is 0 or exceeds {MAX_DECLARED_LEN}"
                )
            }
            SchemaError::EmptyMap => f.write_str("map spec declares no keys"),
            SchemaError::EmptyEnum => f.write_str("enum spec declares no choices"),
            SchemaError::DuplicateEnumChoice { choice } => {
                write!(f, "duplicate enum choice {choice:?}")
            }
            SchemaError::TooDeep { max } => write!(f, "spec nesting exceeds depth {max}"),
            SchemaError::InSlot { slot, inner } => write!(f, "slot {slot:?}: {inner}"),
        }
    }
}

impl std::error::Error for SchemaError {}

/// The registry that owns per-technique param bounds, keyed by [`TechniqueHandle`] — the
/// same handle the engine `Registry` and the loop's region registry key on. Registration
/// validates the set's schema; a malformed set is refused.
#[derive(Default)]
pub struct ParamSpecRegistry {
    map: BTreeMap<TechniqueHandle, ParamSpecSet>,
}

impl ParamSpecRegistry {
    pub fn new() -> Self {
        ParamSpecRegistry::default()
    }

    /// Declare the param bounds for a technique handle. Rejects a malformed set
    /// (registration-time schema check); non-clobbering is the caller's concern (a
    /// re-declare replaces).
    pub fn declare(
        &mut self,
        handle: TechniqueHandle,
        specs: ParamSpecSet,
    ) -> Result<(), SchemaError> {
        specs.validate_schema()?;
        self.map.insert(handle, specs);
        Ok(())
    }

    pub fn get(&self, handle: &TechniqueHandle) -> Option<&ParamSpecSet> {
        self.map.get(handle)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::TechniqueHandle;
    use smash_core::fighter::{FighterId, TechniqueName};

    fn handle() -> TechniqueHandle {
        TechniqueHandle::new(
            FighterId::new("taint-launder"),
            TechniqueName::new("encoding-equiv"),
        )
    }

    #[test]
    fn charset_admits_expected() {
        assert!(Charset::Any.admits("anything 秘密"));
        assert!(Charset::Ascii.admits("abc-123"));
        assert!(!Charset::Ascii.admits("秘密"));
        assert!(Charset::AsciiAlnum.admits("abc123"));
        assert!(!Charset::AsciiAlnum.admits("a-b"));
        assert!(Charset::AsciiPrintable.admits("a ~ b"));
        assert!(!Charset::AsciiPrintable.admits("a\tb"));
    }

    #[test]
    fn well_formed_specs_validate() {
        let set = ParamSpecSet::new()
            .with(
                "recipient",
                ParamSpec::Str {
                    max_len: 256,
                    charset: Charset::Any,
                },
            )
            .with(
                "amount",
                ParamSpec::Int {
                    min: 0,
                    max: 1_000_000,
                },
            )
            .with("flag", ParamSpec::Bool)
            .with(
                "tags",
                ParamSpec::List {
                    max_len: 8,
                    elem: Box::new(ParamSpec::Str {
                        max_len: 32,
                        charset: Charset::AsciiAlnum,
                    }),
                },
            )
            .with(
                "method",
                ParamSpec::Enum {
                    choices: vec!["GET".into(), "POST".into()],
                },
            );
        assert!(set.validate_schema().is_ok());
    }

    #[test]
    fn inverted_int_range_is_rejected() {
        let s = ParamSpec::Int { min: 10, max: 1 };
        assert_eq!(
            s.validate_schema(),
            Err(SchemaError::IntRangeInverted { min: 10, max: 1 })
        );
    }

    #[test]
    fn zero_or_oversized_len_is_rejected() {
        assert_eq!(
            ParamSpec::Str {
                max_len: 0,
                charset: Charset::Any
            }
            .validate_schema(),
            Err(SchemaError::LenOutOfRange { got: 0 })
        );
        assert_eq!(
            ParamSpec::Str {
                max_len: MAX_DECLARED_LEN + 1,
                charset: Charset::Any
            }
            .validate_schema(),
            Err(SchemaError::LenOutOfRange {
                got: MAX_DECLARED_LEN + 1
            })
        );
    }

    #[test]
    fn empty_enum_and_duplicate_choice_are_rejected() {
        assert_eq!(
            ParamSpec::Enum { choices: vec![] }.validate_schema(),
            Err(SchemaError::EmptyEnum)
        );
        assert_eq!(
            ParamSpec::Enum {
                choices: vec!["a".into(), "a".into()]
            }
            .validate_schema(),
            Err(SchemaError::DuplicateEnumChoice { choice: "a".into() })
        );
    }

    #[test]
    fn empty_map_is_rejected() {
        assert_eq!(
            ParamSpec::Map {
                keys: BTreeMap::new()
            }
            .validate_schema(),
            Err(SchemaError::EmptyMap)
        );
    }

    #[test]
    fn excessive_nesting_is_rejected() {
        // Build a List nested past MAX_NESTING_DEPTH.
        let mut spec = ParamSpec::Bool;
        for _ in 0..=MAX_NESTING_DEPTH {
            spec = ParamSpec::List {
                max_len: 1,
                elem: Box::new(spec),
            };
        }
        assert_eq!(
            spec.validate_schema(),
            Err(SchemaError::TooDeep {
                max: MAX_NESTING_DEPTH
            })
        );
    }

    #[test]
    fn schema_error_names_the_offending_slot() {
        let set = ParamSpecSet::new().with("amount", ParamSpec::Int { min: 5, max: 1 });
        match set.validate_schema() {
            Err(SchemaError::InSlot { slot, .. }) => assert_eq!(slot, "amount"),
            other => panic!("expected InSlot, got {other:?}"),
        }
    }

    #[test]
    fn registry_declare_validates_and_rejects_malformed() {
        let mut reg = ParamSpecRegistry::new();
        let good = ParamSpecSet::new().with("amount", ParamSpec::Int { min: 0, max: 10 });
        assert!(reg.declare(handle(), good).is_ok());
        assert_eq!(reg.len(), 1);
        assert!(reg.get(&handle()).is_some());

        let bad = ParamSpecSet::new().with("amount", ParamSpec::Int { min: 10, max: 0 });
        assert!(
            reg.declare(handle(), bad).is_err(),
            "a malformed set must be refused"
        );
    }

    #[test]
    fn depth_is_computed() {
        let flat = ParamSpec::Int { min: 0, max: 1 };
        assert_eq!(flat.depth(), 1);
        let nested = ParamSpec::List {
            max_len: 2,
            elem: Box::new(ParamSpec::Map {
                keys: BTreeMap::from([("k".to_string(), ParamSpec::Bool)]),
            }),
        };
        assert_eq!(nested.depth(), 3);
    }

    #[test]
    fn param_spec_round_trips_json() {
        let s = ParamSpec::List {
            max_len: 4,
            elem: Box::new(ParamSpec::Enum {
                choices: vec!["a".into()],
            }),
        };
        let j = serde_json::to_string(&s).unwrap();
        let back: ParamSpec = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
