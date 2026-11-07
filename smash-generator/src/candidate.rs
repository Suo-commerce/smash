//! The declarative candidate format (boundary §3) and its canonical key.
//!
//! A [`Candidate`] *instantiates an approved template with bounded params* and
//! *selects a registered oracle* — it cannot define a new template or invent an
//! oracle (boundary §3.1: generators discover new **instances**, not new
//! **mechanisms**). It is inert data: nothing here reaches the wire (see the
//! crate-level no-dispatch wall).

use smash_core::capability::Authority;
use smash_core::fighter::{FighterId, OracleId, OracleKind, OracleVersion, TechniqueName};
use std::collections::BTreeMap;

/// Reference to an approved template — a mechanism primitive — by the core handle
/// the engine registry keys on (`FighterId` + `TechniqueName`). The generator
/// *names* a template; admission (in `smash-loop`) maps this to the engine's
/// `TechniqueHandle`. The generator cannot define a template, only reference one.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TemplateRef {
    pub fighter: FighterId,
    pub technique: TechniqueName,
}

impl TemplateRef {
    pub fn new(fighter: FighterId, technique: TechniqueName) -> Self {
        Self { fighter, technique }
    }

    /// A stable, injective rendering for the canonical key.
    fn canonical(&self) -> String {
        format!("{}/{}", self.fighter, self.technique)
    }
}

/// A bounded, typed parameter value. Core-only (no serde) to keep the generator's
/// dependency surface to `smash-core` alone. The loop/engine convert this to the
/// wire's `serde_json::Value` at the adapter boundary.
#[derive(Clone, PartialEq, Debug)]
pub enum ParamValue {
    Str(String),
    Int(i64),
    Bool(bool),
    List(Vec<ParamValue>),
    /// Sorted map — insertion order never affects the canonical key.
    Map(BTreeMap<String, ParamValue>),
}

impl ParamValue {
    /// A stable, type-tagged rendering so that, e.g., `Str("1")` and `Int(1)` never
    /// collide, and container order is fixed. Used only to build the canonical key.
    fn canonical(&self) -> String {
        match self {
            ParamValue::Str(s) => format!("s:{}", escape(s)),
            ParamValue::Int(n) => format!("i:{n}"),
            ParamValue::Bool(b) => format!("b:{b}"),
            ParamValue::List(items) => {
                let inner: Vec<String> = items.iter().map(ParamValue::canonical).collect();
                format!("l:[{}]", inner.join(","))
            }
            ParamValue::Map(map) => {
                // BTreeMap iterates in sorted key order — deterministic.
                let inner: Vec<String> = map
                    .iter()
                    .map(|(k, v)| format!("{}={}", escape(k), v.canonical()))
                    .collect();
                format!("m:{{{}}}", inner.join(","))
            }
        }
    }
}

/// Escape the delimiter characters the canonical rendering uses, so a value
/// containing them cannot forge structure. Minimal and reversible enough for a key.
fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace(',', "\\,")
        .replace('=', "\\=")
        .replace('{', "\\{")
        .replace('}', "\\}")
        .replace('[', "\\[")
        .replace(']', "\\]")
}

/// The oracle a candidate **selects** (mirrors core's `OracleRef` by value so the
/// generator need not construct engine types). The generator selects a registered
/// oracle; it cannot invent one (boundary §3).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OracleBinding {
    pub kind: OracleKind,
    pub id: OracleId,
    pub version: OracleVersion,
}

impl OracleBinding {
    fn canonical(&self) -> String {
        format!("{}/{}/{}", self.kind, self.id, self.version)
    }
}

/// Where a candidate came from — enough to **replay, not regenerate** (boundary §3).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Source {
    /// A mutation of an existing candidate by a named mutator.
    Mutation { of: CanonicalKey, mutator: String },
    /// Derived from a CVE/advisory analog (by handle, snapshot-pinned).
    CveAnalog { advisory: String },
    /// A model-assisted artifact (later; recorded by hash for replay).
    ModelArtifact { hash: String },
    /// Seeded algorithmic generation (the phase-2 default).
    Seed,
}

/// Candidate provenance. The RNG seed makes algorithmic generation replayable.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Provenance {
    pub generator_id: String,
    pub generator_version: u32,
    pub source: Source,
    pub seed: u64,
}

/// A canonical candidate key: `f(declarative content)` only — **epoch- and
/// run-independent** (boundary §0.2). Dedupe and poison bind to this; it is built
/// from the candidate's content, never from any execution identity. Here it is a
/// canonical *string* (deterministic, content-injective); a hash is an optimization
/// a later unit can add without changing its meaning.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct CanonicalKey(pub String);

/// The declarative candidate (boundary §3): instantiates an approved template with
/// bounded params, selects a registered oracle, names its target handle and effect
/// class, and carries provenance. Inert data.
///
/// The no-dispatch wall as a compile-time fact (phase-2 §7): this crate cannot name
/// the engine's transport, because it does not depend on `smash-engine`.
///
/// ```compile_fail
/// // smash-generator has no dependency on smash-engine, so this does not compile:
/// use smash_engine::transport::ControlledTransport;
/// ```
#[derive(Clone, PartialEq, Debug)]
pub struct Candidate {
    pub template: TemplateRef,
    pub params: BTreeMap<String, ParamValue>,
    /// The registered target tool/param handle this probe exercises — not a
    /// free-form URL (boundary §3; `v0.3 §4`).
    pub target_handle: String,
    /// The effect the candidate may have if the target is vulnerable (`v0.3 §5`).
    pub effect_class: Authority,
    /// The oracle this candidate selects (not invents).
    pub oracle: OracleBinding,
    pub provenance: Provenance,
}

impl Candidate {
    /// The canonical candidate key: a deterministic function of the declarative
    /// content — template, params (sorted), target handle, effect class, and oracle
    /// binding. **Provenance is excluded**: two candidates with identical content
    /// but different provenance (one seeded, one a mutation) are the *same* probe
    /// and must dedupe/poison together (boundary §0.2).
    pub fn canonical_key(&self) -> CanonicalKey {
        let params: Vec<String> = self
            .params
            .iter()
            .map(|(k, v)| format!("{}={}", escape(k), v.canonical()))
            .collect();
        let s = format!(
            "tmpl={};params={{{}}};target={};effect={};oracle={}",
            self.template.canonical(),
            params.join(","),
            escape(&self.target_handle),
            self.effect_class,
            self.oracle.canonical(),
        );
        CanonicalKey(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oracle() -> OracleBinding {
        OracleBinding {
            kind: OracleKind::Differential,
            id: OracleId::new("f-b-taint-oracle"),
            version: OracleVersion(1),
        }
    }

    fn candidate_with(params: BTreeMap<String, ParamValue>, source: Source) -> Candidate {
        Candidate {
            template: TemplateRef::new(
                FighterId::new("taint-launder"),
                TechniqueName::new("encoding-equiv"),
            ),
            params,
            target_handle: "web_extract.url".into(),
            effect_class: Authority::Mutating,
            oracle: oracle(),
            provenance: Provenance {
                generator_id: "model-free".into(),
                generator_version: 1,
                source,
                seed: 42,
            },
        }
    }

    fn params(recipient: &str) -> BTreeMap<String, ParamValue> {
        let mut m = BTreeMap::new();
        m.insert("recipient".into(), ParamValue::Str(recipient.into()));
        m
    }

    #[test]
    fn canonical_key_is_content_deterministic() {
        let a = candidate_with(params("ATTACKER-IBAN-12345"), Source::Seed);
        let b = candidate_with(params("ATTACKER-IBAN-12345"), Source::Seed);
        assert_eq!(a.canonical_key(), b.canonical_key());
    }

    #[test]
    fn canonical_key_ignores_provenance() {
        // Same content, different provenance (seed vs mutation) → same key, so they
        // dedupe/poison together (boundary §0.2).
        let seeded = candidate_with(params("x"), Source::Seed);
        let mutated = candidate_with(
            params("x"),
            Source::Mutation { of: CanonicalKey("other".into()), mutator: "encoding-equiv".into() },
        );
        assert_eq!(seeded.canonical_key(), mutated.canonical_key());
    }

    #[test]
    fn canonical_key_changes_with_params() {
        let a = candidate_with(params("ATTACKER_IBAN_12345"), Source::Seed);
        let b = candidate_with(params("ATTACKER-IBAN-12345"), Source::Seed); // laundered
        assert_ne!(a.canonical_key(), b.canonical_key());
    }

    #[test]
    fn param_order_does_not_affect_key() {
        let mut m1 = BTreeMap::new();
        m1.insert("a".into(), ParamValue::Int(1));
        m1.insert("b".into(), ParamValue::Str("x".into()));
        let mut m2 = BTreeMap::new();
        m2.insert("b".into(), ParamValue::Str("x".into()));
        m2.insert("a".into(), ParamValue::Int(1));
        assert_eq!(
            candidate_with(m1, Source::Seed).canonical_key(),
            candidate_with(m2, Source::Seed).canonical_key()
        );
    }

    #[test]
    fn typed_params_do_not_collide() {
        // Str("1") and Int(1) must produce different keys.
        let mut s = BTreeMap::new();
        s.insert("v".into(), ParamValue::Str("1".into()));
        let mut i = BTreeMap::new();
        i.insert("v".into(), ParamValue::Int(1));
        assert_ne!(
            candidate_with(s, Source::Seed).canonical_key(),
            candidate_with(i, Source::Seed).canonical_key()
        );
    }

    #[test]
    fn delimiter_injection_in_values_cannot_forge_structure() {
        // A value containing the canonical delimiters must not collide with a
        // different structure.
        let mut a = BTreeMap::new();
        a.insert("k".into(), ParamValue::Str("v,x=y".into()));
        let mut b = BTreeMap::new();
        b.insert("k".into(), ParamValue::Str("v".into()));
        b.insert("x".into(), ParamValue::Str("y".into()));
        assert_ne!(
            candidate_with(a, Source::Seed).canonical_key(),
            candidate_with(b, Source::Seed).canonical_key()
        );
    }
}
