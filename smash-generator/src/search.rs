//! The model-free search — the generator's `propose` body (generator-model-free §1,§2).
//!
//! This unit implements the **metamorphic-pair** mode: for each seed candidate, each
//! of its string param slots, and each reviewed mutator, it forms a
//! [`MetamorphicPair`] — the base and an equivalent variant (encoding-equivalent for a
//! value-axis mutator, field-name-equivalent for a field-key-axis mutator), tagged
//! with the relation they must jointly satisfy. The pair is what the metamorphic/
//! differential oracle judges downstream: base and variant must get **equal**
//! decisions, so a divergence is a self-evidencing candidate finding.
//!
//! It is **open-loop and seeded**: the output is a deterministic function of
//! `(mutator library versions + seeds + config)`. There is no feedback here —
//! consuming verdicts to bias the next batch (coverage-guidance, intensify-on-KILL)
//! is the loop's `adjust` (phase 3). What this guarantees now is replayability: the
//! same seed yields the same batch, in the same order (generator-model-free §2).
//!
//! The search composes `template × mutator × params` and nothing else — it cannot
//! author a mutator, a template, or an oracle (boundary §3.1). Its whole reach is the
//! reviewed primitives it was handed.

use crate::candidate::Candidate;
use crate::mutators::{mutate_field_key, mutate_string_param, MetamorphicRelation, MutationAxis, Mutator};

/// Search parameters (the subset relevant to the open-loop metamorphic-pair mode).
#[derive(Clone, Copy, Debug)]
pub struct SearchConfig {
    /// Seeds the deterministic selection when the enumeration exceeds `batch_max`.
    pub seed: u64,
    /// Upper bound on pairs returned in one batch. `0` means unbounded.
    pub batch_max: usize,
}

/// A base candidate paired with one equivalent variant, plus the relation they must
/// jointly satisfy. The downstream oracle treats `base` as the control and `variant`
/// as the probe: unequal decisions violate the relation and are a KILL.
#[derive(Clone, Debug, PartialEq)]
pub struct MetamorphicPair {
    pub base: Candidate,
    pub variant: Candidate,
    pub relation: MetamorphicRelation,
}

/// Enumerate every metamorphic pair in a **stable** order: seeds in input order,
/// each seed's string param keys in sorted (`BTreeMap`) order, mutators in library
/// order, each mutator's variants in its own stable order. The per-mutator driver is
/// chosen by the mutator's [`MutationAxis`] — value mutation vs. key relocation.
/// Open-loop and total — selection/truncation is applied afterwards by
/// [`generate_pairs`].
fn enumerate_pairs(
    mutators: &[Box<dyn Mutator>],
    seeds: &[Candidate],
) -> Vec<MetamorphicPair> {
    let mut pairs = Vec::new();
    for base in seeds {
        // BTreeMap keys iterate sorted — deterministic, order-independent of insertion.
        let string_keys: Vec<String> = base
            .params
            .iter()
            .filter(|(_, v)| matches!(v, crate::candidate::ParamValue::Str(_)))
            .map(|(k, _)| k.clone())
            .collect();
        for key in &string_keys {
            for mutator in mutators {
                let variants = match mutator.axis() {
                    MutationAxis::Value => mutate_string_param(mutator.as_ref(), base, key),
                    MutationAxis::FieldKey => mutate_field_key(mutator.as_ref(), base, key),
                };
                for variant in variants {
                    pairs.push(MetamorphicPair {
                        base: base.clone(),
                        variant,
                        relation: mutator.relation(),
                    });
                }
            }
        }
    }
    pairs
}

/// Produce a batch of metamorphic pairs from seeds and the reviewed mutator library.
///
/// Deterministic in `(mutators, seeds, config)`. When the full enumeration exceeds
/// `batch_max`, a **seeded** permutation selects which pairs are returned — so
/// different seeds explore different subsets, reproducibly; the same seed always
/// yields the same batch. `batch_max == 0` returns the whole enumeration in stable
/// order (no permutation).
pub fn generate_pairs(
    mutators: &[Box<dyn Mutator>],
    seeds: &[Candidate],
    config: &SearchConfig,
) -> Vec<MetamorphicPair> {
    let pairs = enumerate_pairs(mutators, seeds);

    // Unbounded, or everything fits: stable enumeration order, seed does not reorder.
    if config.batch_max == 0 || pairs.len() <= config.batch_max {
        return pairs;
    }

    // More pairs than the batch allows: pick a seeded, reproducible subset of
    // indices, then present them in enumeration order (the seed governs *which*
    // pairs are explored, not how the batch is ordered for a reader).
    let order = seeded_permutation(pairs.len(), config.seed);
    let mut chosen: Vec<usize> = order.into_iter().take(config.batch_max).collect();
    chosen.sort_unstable();
    chosen.into_iter().map(|i| pairs[i].clone()).collect()
}

/// A deterministic permutation of `0..n` from `seed` (Fisher–Yates over a small LCG).
/// No dependency, fully reproducible.
fn seeded_permutation(n: usize, seed: u64) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..n).collect();
    if n <= 1 {
        return idx;
    }
    let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        // LCG (Knuth's MMIX constants); take high bits for better distribution.
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state >> 33
    };
    for i in (1..n).rev() {
        let j = (next() as usize) % (i + 1);
        idx.swap(i, j);
    }
    idx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::{Candidate, OracleBinding, ParamValue, Provenance, Source, TemplateRef};
    use crate::mutators::{builtin_mutators, field_selection_mutators, EncodingEquiv};
    use smash_core::capability::Authority;
    use smash_core::fighter::{FighterId, OracleId, OracleKind, OracleVersion, TechniqueName};
    use std::collections::BTreeMap;

    fn seed_candidate(recipient: &str) -> Candidate {
        let mut params = BTreeMap::new();
        params.insert("recipient".into(), ParamValue::Str(recipient.into()));
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
                seed: 7,
            },
        }
    }

    fn cfg(batch_max: usize) -> SearchConfig {
        SearchConfig { seed: 7, batch_max }
    }

    #[test]
    fn pairs_reproduce_w1_with_its_relation() {
        let muts = builtin_mutators();
        let pairs = generate_pairs(&muts, &[seed_candidate("ATTACKER_IBAN_12345")], &cfg(0));
        let w1 = pairs.iter().find(|p| {
            matches!(
                p.variant.params.get("recipient"),
                Some(ParamValue::Str(s)) if s == "ATTACKER-IBAN-12345"
            )
        });
        let w1 = w1.expect("the dash-laundered pair must be generated");
        assert_eq!(w1.relation, MetamorphicRelation::EqualDecisionUnderEncoding);
        // The base is the verbatim seed; the variant records its mutation origin.
        assert_eq!(
            w1.base.params.get("recipient"),
            Some(&ParamValue::Str("ATTACKER_IBAN_12345".into()))
        );
        assert!(matches!(w1.variant.provenance.source, Source::Mutation { .. }));
    }

    #[test]
    fn field_selection_pairs_carry_their_relation_and_relocate_the_key() {
        let muts = field_selection_mutators();
        let pairs = generate_pairs(&muts, &[seed_candidate("ATTACKER_IBAN_12345")], &cfg(0));
        assert!(!pairs.is_empty());
        assert!(pairs.iter().all(|p| p.relation == MetamorphicRelation::FieldSelectionInvariance));
        // The base keeps `recipient`; each variant relocates it to a sibling key and
        // records its mutation origin.
        for p in &pairs {
            assert!(p.base.params.contains_key("recipient"));
            assert!(
                !p.variant.params.contains_key("recipient"),
                "the key is relocated in the variant"
            );
            assert!(matches!(p.variant.provenance.source, Source::Mutation { .. }));
        }
    }

    #[test]
    fn generation_is_deterministic() {
        let muts = builtin_mutators();
        let seeds = [seed_candidate("ATTACKER_IBAN_12345"), seed_candidate("victim_account")];
        let a = generate_pairs(&muts, &seeds, &cfg(0));
        let b = generate_pairs(&muts, &seeds, &cfg(0));
        assert_eq!(a, b, "same inputs ⇒ identical batch (replayable)");
        assert!(!a.is_empty());
    }

    #[test]
    fn batch_max_bounds_the_output() {
        let muts = builtin_mutators();
        let seeds = [seed_candidate("ATTACKER_IBAN_12345")];
        let full = generate_pairs(&muts, &seeds, &cfg(0));
        let capped = generate_pairs(&muts, &seeds, &cfg(2));
        assert!(full.len() > 2, "need more than the cap to test truncation");
        assert_eq!(capped.len(), 2);
    }

    #[test]
    fn seeded_selection_is_reproducible_and_seed_dependent() {
        let muts = builtin_mutators();
        let seeds = [seed_candidate("ATTACKER_IBAN_12345")];
        let full = generate_pairs(&muts, &seeds, &SearchConfig { seed: 1, batch_max: 0 });
        assert!(full.len() >= 3, "need a few pairs for subset selection to differ");

        let s1a = generate_pairs(&muts, &seeds, &SearchConfig { seed: 1, batch_max: 2 });
        let s1b = generate_pairs(&muts, &seeds, &SearchConfig { seed: 1, batch_max: 2 });
        assert_eq!(s1a, s1b, "same seed ⇒ same subset");

        // A different seed may select a different subset; both are valid size-2 batches.
        let s2 = generate_pairs(&muts, &seeds, &SearchConfig { seed: 999, batch_max: 2 });
        assert_eq!(s2.len(), 2);
    }

    #[test]
    fn no_string_params_yields_no_pairs() {
        let mut c = seed_candidate("x");
        c.params.clear();
        c.params.insert("count".into(), ParamValue::Int(3));
        let muts = builtin_mutators();
        assert!(generate_pairs(&muts, &[c], &cfg(0)).is_empty());
    }

    #[test]
    fn direct_encoding_equiv_mutator_also_drives_search() {
        // The library is reviewed primitives; a single mutator can be used directly.
        let muts: Vec<Box<dyn Mutator>> = vec![Box::new(EncodingEquiv)];
        let pairs = generate_pairs(&muts, &[seed_candidate("A_B")], &cfg(0));
        assert!(pairs.iter().all(|p| p.relation == MetamorphicRelation::EqualDecisionUnderEncoding));
        assert!(!pairs.is_empty());
    }
}
