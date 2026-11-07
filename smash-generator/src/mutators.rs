//! The mutator library — reviewed transformation primitives (generator-model-free §3).
//!
//! A mutator captures a *known transformation class* as a reusable search axis: it
//! takes a value and produces equivalent/varied forms within a template's declared
//! slots. The generator **composes** `template × mutator × params`; it does not
//! author mutators (boundary §3.1). Each mutator is reviewed code — admitting one is
//! editing the trusted base, the same bar as a template — so a model may *draft* a
//! mutator but a human admits it.
//!
//! The highest-value mutators pair with a **metamorphic relation** that doubles as
//! the oracle (design-note §6.2): the relation says what must hold across the
//! transformation, so a violation is self-evidencing. `encoding-equiv` is the first:
//! it captures the F-B/W1 class (a tainted value laundered through an equivalent
//! encoding) and carries the relation *"equivalent encodings must get equal gate
//! decisions."* `field-select` is the second: it captures the F-B/W2 class (a
//! sensitive value relocated to a sibling field name) and carries the relation *"a
//! sensitive value must get the same decision under any field name."* The two differ
//! in the **axis** they rewrite — a param's value vs. its key — not in the machinery.

use crate::candidate::{Candidate, ParamValue, Source};

/// The metamorphic relation a mutator's variants must satisfy — the correctness
/// test that turns a transformation into a discovery oracle. A variant decided
/// *differently* from its base violates the relation and is a candidate finding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MetamorphicRelation {
    /// Encoding-equivalent inputs must receive equal gate decisions. A variant
    /// approved where its base was withheld is the W1 laundering class — a KILL.
    EqualDecisionUnderEncoding,
    /// Relocating a sensitive value to a differently-named field must receive the same
    /// gate decision. A variant approved under a renamed key where its base was
    /// withheld is the W2 field-selection class — a KILL.
    FieldSelectionInvariance,
    // Future reviewed relations compose here without widening the generator's reach:
    // PermissionMonotonicity, ArgumentOrderInvariance, RepresentationEquivalence, …
}

/// The part of a candidate a mutator rewrites. [`Mutator::string_variants`] returns
/// replacement strings in both cases; the axis says whether they replace a string
/// param's *value* (keeping its key) or its *key* (keeping its value), so the search
/// applies the right transformation and the resulting pair stays well-formed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MutationAxis {
    /// Rewrite a string param's value, keeping its key (representation equivalence).
    Value,
    /// Rename a string param's key, keeping its value (field selection).
    FieldKey,
}

/// A reviewed transformation primitive. `string_variants` is the mechanism; the
/// generator and search drive it. Deterministic by contract: the same input yields
/// the same variants in the same order, so a seeded search is replayable.
pub trait Mutator {
    /// Stable kebab-case identifier, recorded in candidate provenance.
    fn id(&self) -> &'static str;

    /// The metamorphic relation this mutator's variants are expected to satisfy.
    fn relation(&self) -> MetamorphicRelation;

    /// Which axis of the candidate this mutator transforms: a string param's *value*
    /// (the default — encoding/representation equivalences) or its *field key* (the
    /// field-selection class, where the sensitive value is relocated to a sibling
    /// key). The search uses this to pick the driver; `string_variants` produces the
    /// replacement strings either way (new values, or new key names).
    fn axis(&self) -> MutationAxis {
        MutationAxis::Value
    }

    /// The equivalence-class variants of a string leaf, **excluding the input
    /// itself**, deduplicated, in a stable order.
    fn string_variants(&self, input: &str) -> Vec<String>;
}

/// `encoding-equiv` — the F-B/W1 class. Produces encoding-equivalent spellings of a
/// value (the forms a human reads as "the same thing" but a naive substring/exact
/// check does not): separator swaps, case folds, and separator stripping.
///
/// Relation: [`MetamorphicRelation::EqualDecisionUnderEncoding`]. Axis: value.
pub struct EncodingEquiv;

impl Mutator for EncodingEquiv {
    fn id(&self) -> &'static str {
        "encoding-equiv"
    }

    fn relation(&self) -> MetamorphicRelation {
        MetamorphicRelation::EqualDecisionUnderEncoding
    }

    fn string_variants(&self, input: &str) -> Vec<String> {
        // Each transform is a reviewed, deterministic encoding equivalence. Order is
        // fixed; `push_unique` drops duplicates and the input itself.
        let transforms: [fn(&str) -> String; 5] = [
            |s| s.replace('_', "-"),            // underscores → dashes (the W1 probe)
            |s| s.replace('-', "_"),            // dashes → underscores
            |s| s.to_lowercase(),               // case fold down
            |s| s.to_uppercase(),               // case fold up
            |s| s.replace(['_', '-', ' '], ""), // strip separators
        ];

        let mut out: Vec<String> = Vec::new();
        let mut push_unique = |v: String| {
            if v != input && !out.contains(&v) {
                out.push(v);
            }
        };
        for t in transforms {
            push_unique(t(input));
        }
        out
    }
}

/// `field-select` — the F-B/W2 sensitive-field-selection class. Produces sibling
/// **key names** for a sensitive field: the same value relocated to a key a naive,
/// exact-match field allowlist does not cover, while a semantic (provenance-by-
/// default) gate — one that matches on the field's *meaning*, not its literal name —
/// still catches it. The mutated axis is the key, not the value.
///
/// Relation: [`MetamorphicRelation::FieldSelectionInvariance`]. Axis: field key.
pub struct FieldSelect;

impl Mutator for FieldSelect {
    fn id(&self) -> &'static str {
        "field-select"
    }

    fn relation(&self) -> MetamorphicRelation {
        MetamorphicRelation::FieldSelectionInvariance
    }

    fn axis(&self) -> MutationAxis {
        MutationAxis::FieldKey
    }

    fn string_variants(&self, input: &str) -> Vec<String> {
        // Reviewed, deterministic sibling key names. Each keeps the original key as a
        // substring, so a gate matching the field's meaning (not its literal name)
        // still escalates — the variants separate a name-allowlist gate from a
        // semantic one. Order is fixed; `push_unique` drops the input and duplicates.
        let transforms: [fn(&str) -> String; 3] = [
            |k| format!("{k}_note"), // recipient → recipient_note (sibling free-text)
            |k| format!("{k}_copy"), // recipient → recipient_copy
            |k| format!("x_{k}"),    // recipient → x_recipient (vendor-prefixed)
        ];

        let mut out: Vec<String> = Vec::new();
        let mut push_unique = |v: String| {
            if v != input && !out.contains(&v) {
                out.push(v);
            }
        };
        for t in transforms {
            push_unique(t(input));
        }
        out
    }
}

/// The built-in, reviewed **value-equivalence** mutator library (W1's axis). Extending
/// it is a reviewed TCB change (a human admits each addition); the generator never
/// adds a mutator at runtime. Field-selection mutators (W2) live in
/// [`field_selection_mutators`] so a value-equivalence search and a field-selection
/// search each drive only their own axis — a later unit may merge the two once regions
/// are keyed per technique.
pub fn builtin_mutators() -> Vec<Box<dyn Mutator>> {
    vec![Box::new(EncodingEquiv)]
}

/// The reviewed **field-selection** mutator library (W2's axis), kept separate from
/// [`builtin_mutators`] — see its note. Same reviewed-TCB bar.
pub fn field_selection_mutators() -> Vec<Box<dyn Mutator>> {
    vec![Box::new(FieldSelect)]
}

/// Apply a mutator to one **string** param of a base candidate, producing a variant
/// candidate per equivalence-class spelling. Each variant is identical to the base
/// except for the mutated value, and carries `Source::Mutation` provenance pinning
/// the base's canonical key and the mutator id (so the search is replayable and a
/// finding traces to its origin). Non-string params and absent keys yield no
/// variants.
///
/// This is the **value-axis** driver ([`MutationAxis::Value`]); the field-key axis is
/// [`mutate_field_key`].
pub fn mutate_string_param(
    mutator: &dyn Mutator,
    base: &Candidate,
    param_key: &str,
) -> Vec<Candidate> {
    let Some(ParamValue::Str(current)) = base.params.get(param_key) else {
        return Vec::new();
    };
    let base_key = base.canonical_key();
    mutator
        .string_variants(current)
        .into_iter()
        .map(|variant| {
            let mut c = base.clone();
            c.params.insert(param_key.to_string(), ParamValue::Str(variant));
            c.provenance.source = Source::Mutation {
                of: base_key.clone(),
                mutator: mutator.id().to_string(),
            };
            c
        })
        .collect()
}

/// Apply a **field-key** mutator to one string param of a base candidate, producing a
/// variant per sibling key name. Each variant **relocates** the value: the original
/// key is removed and the value re-inserted under the new key, so base and variant
/// carry the same value under different keys (the field-selection relation). Carries
/// `Source::Mutation` provenance pinning the base key and the mutator id. A variant
/// whose new key equals the original or already exists on the base is skipped.
/// Non-string params and absent keys yield no variants.
///
/// This is the **field-key-axis** driver ([`MutationAxis::FieldKey`]); the value axis
/// is [`mutate_string_param`].
pub fn mutate_field_key(
    mutator: &dyn Mutator,
    base: &Candidate,
    param_key: &str,
) -> Vec<Candidate> {
    let Some(ParamValue::Str(value)) = base.params.get(param_key) else {
        return Vec::new();
    };
    let value = value.clone();
    let base_key = base.canonical_key();
    mutator
        .string_variants(param_key)
        .into_iter()
        .filter(|new_key| new_key != param_key && !base.params.contains_key(new_key))
        .map(|new_key| {
            let mut c = base.clone();
            c.params.remove(param_key);
            c.params.insert(new_key, ParamValue::Str(value.clone()));
            c.provenance.source = Source::Mutation {
                of: base_key.clone(),
                mutator: mutator.id().to_string(),
            };
            c
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::{OracleBinding, Provenance, TemplateRef};
    use smash_core::capability::Authority;
    use smash_core::fighter::{FighterId, OracleId, OracleKind, OracleVersion, TechniqueName};
    use std::collections::BTreeMap;

    #[test]
    fn encoding_equiv_produces_the_w1_dash_variant() {
        // The exact F-B/W1 laundering: underscores → dashes.
        let v = EncodingEquiv.string_variants("ATTACKER_IBAN_12345");
        assert!(v.contains(&"ATTACKER-IBAN-12345".to_string()));
        // And it strips separators as another equivalence.
        assert!(v.contains(&"ATTACKERIBAN12345".to_string()));
    }

    #[test]
    fn variants_exclude_the_input_and_dedupe() {
        // An all-lowercase, separator-free input: several transforms collapse to the
        // input; none of those may appear, and no duplicates.
        let v = EncodingEquiv.string_variants("abc");
        assert!(!v.contains(&"abc".to_string()), "input itself is never a variant");
        let mut sorted = v.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), v.len(), "no duplicate variants");
    }

    #[test]
    fn string_variants_are_deterministic_and_stable() {
        let a = EncodingEquiv.string_variants("ATTACKER_IBAN");
        let b = EncodingEquiv.string_variants("ATTACKER_IBAN");
        assert_eq!(a, b, "same input ⇒ identical variants in identical order (replayable)");
    }

    #[test]
    fn encoding_equiv_declares_its_relation() {
        assert_eq!(EncodingEquiv.relation(), MetamorphicRelation::EqualDecisionUnderEncoding);
        assert_eq!(EncodingEquiv.id(), "encoding-equiv");
    }

    #[test]
    fn encoding_equiv_is_value_axis_by_default() {
        assert_eq!(EncodingEquiv.axis(), MutationAxis::Value);
    }

    #[test]
    fn field_select_relocates_to_sibling_keys() {
        let v = FieldSelect.string_variants("recipient");
        assert!(v.contains(&"recipient_note".to_string()));
        assert!(v.contains(&"x_recipient".to_string()));
        // Every sibling keeps the original key as a substring (so a semantic gate
        // still catches it) and none equals the input.
        assert!(v.iter().all(|k| k.contains("recipient") && k != "recipient"));
    }

    #[test]
    fn field_select_declares_its_axis_and_relation() {
        assert_eq!(FieldSelect.axis(), MutationAxis::FieldKey);
        assert_eq!(FieldSelect.relation(), MetamorphicRelation::FieldSelectionInvariance);
        assert_eq!(FieldSelect.id(), "field-select");
    }

    fn base_candidate() -> Candidate {
        let mut params = BTreeMap::new();
        params.insert("recipient".into(), ParamValue::Str("ATTACKER_IBAN_12345".into()));
        Candidate {
            template: TemplateRef::new(
                FighterId::new("taint-launder"),
                TechniqueName::new("encoding-equiv"),
            ),
            params,
            target_handle: "web_extract.url".into(),
            effect_class: Authority::Mutating,
            oracle: OracleBinding {
                kind: OracleKind::Differential,
                id: OracleId::new("f-b-taint-oracle"),
                version: OracleVersion(1),
            },
            provenance: Provenance {
                generator_id: "model-free".into(),
                generator_version: 1,
                source: Source::Seed,
                seed: 42,
            },
        }
    }

    #[test]
    fn mutating_a_string_param_yields_variant_candidates_with_mutation_provenance() {
        let base = base_candidate();
        let base_key = base.canonical_key();
        let variants = mutate_string_param(&EncodingEquiv, &base, "recipient");
        assert!(!variants.is_empty());

        // At least one variant is the W1 dash form, and every variant differs from
        // the base by key and records its origin.
        let mut saw_dash = false;
        for c in &variants {
            assert_ne!(c.canonical_key(), base_key, "a variant must differ from its base");
            match &c.provenance.source {
                Source::Mutation { of, mutator } => {
                    assert_eq!(of, &base_key, "provenance pins the base key");
                    assert_eq!(mutator, "encoding-equiv");
                }
                other => panic!("expected Mutation provenance, got {other:?}"),
            }
            if let Some(ParamValue::Str(s)) = c.params.get("recipient") {
                if s == "ATTACKER-IBAN-12345" {
                    saw_dash = true;
                }
            }
        }
        assert!(saw_dash, "the W1 laundered variant must be among the mutations");
    }

    #[test]
    fn mutate_field_key_relocates_the_value_under_a_new_key() {
        let base = base_candidate(); // { recipient: "ATTACKER_IBAN_12345" }
        let base_key = base.canonical_key();
        let variants = mutate_field_key(&FieldSelect, &base, "recipient");
        assert!(!variants.is_empty());
        for c in &variants {
            // The original key is gone; the value rides under a sibling key, unchanged.
            assert!(!c.params.contains_key("recipient"), "the original key is relocated");
            assert!(
                c.params.values().any(
                    |v| matches!(v, ParamValue::Str(s) if s == "ATTACKER_IBAN_12345")
                ),
                "the sensitive value is preserved under the new key"
            );
            assert_ne!(c.canonical_key(), base_key, "a variant must differ from its base");
            match &c.provenance.source {
                Source::Mutation { of, mutator } => {
                    assert_eq!(of, &base_key, "provenance pins the base key");
                    assert_eq!(mutator, "field-select");
                }
                other => panic!("expected Mutation provenance, got {other:?}"),
            }
        }
    }

    #[test]
    fn mutating_a_nonstring_or_absent_param_yields_nothing() {
        let mut base = base_candidate();
        base.params.insert("count".into(), ParamValue::Int(3));
        assert!(mutate_string_param(&EncodingEquiv, &base, "count").is_empty());
        assert!(mutate_string_param(&EncodingEquiv, &base, "missing").is_empty());
        assert!(mutate_field_key(&FieldSelect, &base, "count").is_empty());
        assert!(mutate_field_key(&FieldSelect, &base, "missing").is_empty());
    }

    #[test]
    fn builtin_library_contains_encoding_equiv() {
        let lib = builtin_mutators();
        assert!(lib.iter().any(|m| m.id() == "encoding-equiv"));
    }

    #[test]
    fn field_selection_library_contains_field_select() {
        let lib = field_selection_mutators();
        assert!(lib.iter().any(|m| m.id() == "field-select"));
    }
}
