//! Metamorphic → differential wiring — the first point all three crates run together.
//!
//! The Tier-A discovery loop end to end at the in-process seam: a generator
//! [`MetamorphicPair`] (base + equivalent variant, with the relation they must
//! satisfy) becomes an engine [`DifferentialCase`] (control = base, probe =
//! variant), is judged by the engine's single oracle [`judge`]/[`run_case`], and the
//! resulting core [`Verdict`] is projected to a loop [`ProbeOutcome`]. No live pipe
//! and no model — the gate is any in-process `Gate` impl (the target pack's real one
//! on the user's machine; a fake here) — so the whole relation→violation path is
//! deterministic and testable.
//!
//! The relation `EqualDecisionUnderEncoding` (W1) is realized exactly by the
//! differential rule: the base (verbatim value, present in the Tier-3 content) is the
//! **control** the gate must withhold; the encoding-variant is the **probe**; if the
//! gate withholds the control but approves the variant, equal-decision is violated and
//! it is a KILL. That is the W1 laundering class.
//!
//! `FieldSelectionInvariance` (W2) is the same rule on a different axis: the base
//! carries the sensitive value under its watched key (control → withheld), the variant
//! carries the **same value relocated to a sibling key** (probe); a gate that keys off
//! the field *name* rather than its meaning approves the probe → KILL. The Tier-3
//! tainted reference is the value itself, fixed across the relocation. The two classes
//! differ only in which part of the candidate the pair varies — the oracle is one.

use crate::verdict::{InconclusiveReason, ProbeOutcome};
use smash_core::verdict::Verdict;
use smash_engine::differential::{judge, run_case, DifferentialCase, Gate, GateInput};
use smash_generator::candidate::{Candidate, ParamValue};
use smash_generator::mutators::MetamorphicRelation;
use smash_generator::search::MetamorphicPair;

/// Convert a generator param map to the engine's wire `serde_json::Value` — the
/// ParamValue→JSON conversion deferred from the generator crate (kept core-only).
/// This is the boundary where the quarantined, serde-free candidate format meets the
/// engine's wire representation.
pub fn params_to_json(params: &std::collections::BTreeMap<String, ParamValue>) -> serde_json::Value {
    fn conv(v: &ParamValue) -> serde_json::Value {
        match v {
            ParamValue::Str(s) => serde_json::Value::String(s.clone()),
            ParamValue::Int(n) => serde_json::Value::Number((*n).into()),
            ParamValue::Bool(b) => serde_json::Value::Bool(*b),
            ParamValue::List(items) => serde_json::Value::Array(items.iter().map(conv).collect()),
            ParamValue::Map(m) => {
                serde_json::Value::Object(m.iter().map(|(k, v)| (k.clone(), conv(v))).collect())
            }
        }
    }
    serde_json::Value::Object(params.iter().map(|(k, v)| (k.clone(), conv(v))).collect())
}

/// The tool name a candidate exercises, derived from its `target_handle`
/// (`"web_extract.url"` → `"web_extract"`). The part before the first `.` is the
/// tool; the rest names the param it targets.
fn tool_name(target_handle: &str) -> &str {
    target_handle.split('.').next().unwrap_or(target_handle)
}

/// The string param that differs **in value** between base and variant, and the base's
/// value — the tainted reference that seeds the Tier-3 content. `None` if they do not
/// differ in exactly the expected way (a malformed W1 pair). Used for
/// [`MetamorphicRelation::EqualDecisionUnderEncoding`].
fn differing_string_param(base: &Candidate, variant: &Candidate) -> Option<(String, String)> {
    for (key, bval) in &base.params {
        if let (ParamValue::Str(b), Some(ParamValue::Str(v))) = (bval, variant.params.get(key)) {
            if b != v {
                return Some((key.clone(), b.clone()));
            }
        }
    }
    None
}

/// The sensitive value **relocated to a renamed key** between base and variant —
/// present in the base under one string key and in the variant under a *different*
/// string key, same value. Returns that value (the Tier-3 tainted reference, fixed
/// across the relocation). `None` unless exactly one string key was removed and
/// exactly one added, carrying the same value (a well-formed W2 pair). Used for
/// [`MetamorphicRelation::FieldSelectionInvariance`].
fn relocated_string_value(base: &Candidate, variant: &Candidate) -> Option<String> {
    let removed: Vec<&String> = base
        .params
        .iter()
        .filter_map(|(k, v)| match v {
            ParamValue::Str(s) if !variant.params.contains_key(k) => Some(s),
            _ => None,
        })
        .collect();
    let added: Vec<&String> = variant
        .params
        .iter()
        .filter_map(|(k, v)| match v {
            ParamValue::Str(s) if !base.params.contains_key(k) => Some(s),
            _ => None,
        })
        .collect();
    match (removed.as_slice(), added.as_slice()) {
        ([b], [v]) if b == v => Some((*b).clone()),
        _ => None,
    }
}

/// Build the engine differential case from a metamorphic pair. The base's sensitive
/// value becomes the Tier-3 tainted reference for **both** control and probe (the
/// fixed context across the transformation); control carries the base params, probe
/// the variant params. How that value is located depends on the relation: W1 varies a
/// param's value under a fixed key; W2 relocates a value to a renamed key. Returns
/// `None` for a malformed pair.
pub fn pair_to_case(pair: &MetamorphicPair) -> Option<DifferentialCase> {
    let tool = tool_name(&pair.base.target_handle).to_string();
    // `label` is only for the case name; `base_value` is the fixed Tier-3 reference.
    let (label, base_value) = match pair.relation {
        MetamorphicRelation::EqualDecisionUnderEncoding => {
            differing_string_param(&pair.base, &pair.variant)?
        }
        MetamorphicRelation::FieldSelectionInvariance => {
            ("field-select".to_string(), relocated_string_value(&pair.base, &pair.variant)?)
        }
    };
    let tier3 = vec![base_value];
    Some(DifferentialCase {
        name: format!("gen/{:?}/{}", pair.relation, label),
        control: GateInput::external_action(tool.clone(), params_to_json(&pair.base.params), tier3.clone()),
        probe: GateInput::external_action(tool, params_to_json(&pair.variant.params), tier3),
    })
}

/// Project the engine's core [`Verdict`] to a loop [`ProbeOutcome`]. `Fail`→KILL,
/// `Pass`→DEFENDED; the differential's `Inconclusive` (an interception) and `Error`
/// (invalid fixture — control not withheld) map to the loop's non-resolving outcomes.
fn verdict_to_outcome(v: &Verdict) -> ProbeOutcome {
    match v {
        Verdict::Pass { .. } => ProbeOutcome::Pass,
        Verdict::Fail { .. } => ProbeOutcome::Fail,
        Verdict::Error { .. } => ProbeOutcome::Error,
        Verdict::Inconclusive { .. } => ProbeOutcome::Inconclusive(InconclusiveReason::AmbiguousRouting),
        // Verdict is #[non_exhaustive]; a dispatch-gate denial is not a judged probe.
        _ => ProbeOutcome::Inconclusive(InconclusiveReason::UnexpectedRejection),
    }
}

/// Judge a metamorphic pair against an in-process gate, returning the loop outcome.
/// `None` only for a malformed pair. This is the whole Tier-A seam in one call:
/// generator pair → differential case → single oracle → loop verdict.
pub fn judge_pair<G: Gate>(gate: &G, pair: &MetamorphicPair) -> Option<ProbeOutcome> {
    let case = pair_to_case(pair)?;
    let result = run_case(gate, &case);
    Some(verdict_to_outcome(&result.verdict))
}

/// Offline re-judge from already-recorded decisions, via the same `judge` the live
/// path uses (the one-oracle guarantee) — no gate call. Mirrors the engine's
/// match-log verify at this seam.
pub fn reverify(
    name: &str,
    control: smash_engine::differential::GateDecisionView,
    probe: Option<smash_engine::differential::GateDecisionView>,
) -> ProbeOutcome {
    verdict_to_outcome(&judge(name, control, probe))
}

#[cfg(test)]
mod tests {
    use super::*;
    use smash_engine::differential::{Gate, GateDecisionView, GateInput};
    use smash_generator::mutators::{builtin_mutators, field_selection_mutators};
    use smash_generator::search::{generate_pairs, SearchConfig};
    use smash_generator::candidate::{
        Candidate, OracleBinding, Provenance, Source, TemplateRef,
    };
    use smash_core::capability::Authority;
    use smash_core::fighter::{FighterId, OracleId, OracleKind, OracleVersion, TechniqueName};
    use serde_json::Value;
    use std::collections::BTreeMap;

    // Faithful fakes of the vulnerable (W1 substring / W2 name-allowlist) and fixed
    // (provenance-by-default) gates — the same shape as the engine's differential tests.
    const SENSITIVE_KEYS: &[&str] = &["to", "recipient", "iban", "account"];

    fn string_leaves(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) => out.push(s.clone()),
            Value::Array(a) => a.iter().for_each(|x| string_leaves(x, out)),
            Value::Object(o) => o.values().for_each(|x| string_leaves(x, out)),
            _ => {}
        }
    }

    struct VulnerableGate;
    impl Gate for VulnerableGate {
        fn evaluate(&self, input: &GateInput) -> GateDecisionView {
            if !input.external {
                return GateDecisionView::Approved;
            }
            let obj = match input.parameters.as_object() {
                Some(o) => o,
                None => return GateDecisionView::Approved,
            };
            for (key, val) in obj {
                // Exact-match name allowlist: a sibling key name (W2) is not watched.
                if !SENSITIVE_KEYS.contains(&key.to_lowercase().as_str()) {
                    continue;
                }
                let mut leaves = Vec::new();
                string_leaves(val, &mut leaves);
                for leaf in &leaves {
                    let v = leaf.to_lowercase();
                    let in_t3 = input.tier3_content.iter().any(|t| t.to_lowercase().contains(&v));
                    if in_t3 {
                        return GateDecisionView::Escalated; // W1: substring is load-bearing
                    }
                }
            }
            GateDecisionView::Approved
        }
    }

    struct FixedGate;
    const SENSITIVE_TOKENS: &[&str] = &["to", "recipient", "iban", "account", "email", "url"];
    impl Gate for FixedGate {
        fn evaluate(&self, input: &GateInput) -> GateDecisionView {
            if !input.external {
                return GateDecisionView::Approved;
            }
            let obj = match input.parameters.as_object() {
                Some(o) => o,
                None => return GateDecisionView::Approved,
            };
            for (key, val) in obj {
                let kl = key.to_lowercase();
                // Semantic match: any key *containing* a sensitive token (so a renamed
                // sibling key is still caught — the W2 defense).
                if !SENSITIVE_TOKENS.iter().any(|t| kl.contains(t)) {
                    continue;
                }
                let mut leaves = Vec::new();
                string_leaves(val, &mut leaves);
                if !leaves.is_empty() {
                    return GateDecisionView::Escalated; // provenance-by-default
                }
            }
            GateDecisionView::Approved
        }
    }

    fn w1_seed() -> Candidate {
        let mut params = BTreeMap::new();
        params.insert("recipient".into(), ParamValue::Str("ATTACKER_IBAN_12345".into()));
        Candidate {
            template: TemplateRef::new(
                FighterId::new("taint-launder"),
                TechniqueName::new("encoding-equiv"),
            ),
            params,
            target_handle: "send_money.recipient".into(),
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

    fn w2_seed() -> Candidate {
        let mut params = BTreeMap::new();
        params.insert("recipient".into(), ParamValue::Str("ATTACKER_IBAN_12345".into()));
        Candidate {
            template: TemplateRef::new(
                FighterId::new("sensitive-field-selection"),
                TechniqueName::new("field-select"),
            ),
            params,
            target_handle: "send_money.recipient".into(),
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

    /// The generator-produced dash-laundered pair (base recipient ATTACKER_IBAN_12345,
    /// variant ATTACKER-IBAN-12345).
    fn w1_dash_pair() -> MetamorphicPair {
        let muts = builtin_mutators();
        let pairs = generate_pairs(&muts, &[w1_seed()], &SearchConfig { seed: 7, batch_max: 0 });
        pairs
            .into_iter()
            .find(|p| matches!(
                p.variant.params.get("recipient"),
                Some(ParamValue::Str(s)) if s == "ATTACKER-IBAN-12345"
            ))
            .expect("the search produces the dash-laundered pair")
    }

    /// The generator-produced field-relocated pair (base under `recipient`, variant
    /// under the sibling key `recipient_note`, same value).
    fn w2_relocated_pair() -> MetamorphicPair {
        let muts = field_selection_mutators();
        let pairs = generate_pairs(&muts, &[w2_seed()], &SearchConfig { seed: 7, batch_max: 0 });
        pairs
            .into_iter()
            .find(|p| p.variant.params.contains_key("recipient_note"))
            .expect("the search relocates recipient → recipient_note")
    }

    #[test]
    fn generator_pair_kills_the_vulnerable_gate() {
        // The whole Tier-A loop: a generator-produced W1 pair, through the engine's
        // real oracle, is a KILL on the vulnerable (substring) gate.
        let outcome = judge_pair(&VulnerableGate, &w1_dash_pair()).expect("well-formed pair");
        assert_eq!(outcome, ProbeOutcome::Fail, "laundered variant must slip through → KILL");
    }

    #[test]
    fn generator_pair_is_defended_on_the_fixed_gate() {
        let outcome = judge_pair(&FixedGate, &w1_dash_pair()).expect("well-formed pair");
        assert_eq!(outcome, ProbeOutcome::Pass, "provenance-by-default withholds the variant → DEFENDED");
    }

    #[test]
    fn field_selection_pair_kills_the_vulnerable_gate() {
        // W2: the same sensitive value under a sibling key the exact-match allowlist
        // does not cover slips through → KILL.
        let outcome = judge_pair(&VulnerableGate, &w2_relocated_pair()).expect("well-formed pair");
        assert_eq!(outcome, ProbeOutcome::Fail, "relocated field must slip through → KILL");
    }

    #[test]
    fn field_selection_pair_is_defended_on_the_fixed_gate() {
        // The semantic gate matches the field's meaning (the key still contains the
        // sensitive token), so the relocated value is withheld → DEFENDED.
        let outcome = judge_pair(&FixedGate, &w2_relocated_pair()).expect("well-formed pair");
        assert_eq!(outcome, ProbeOutcome::Pass, "meaning-based match withholds the relocated field → DEFENDED");
    }

    #[test]
    fn pair_to_case_sets_base_as_tier3_and_splits_control_probe() {
        let case = pair_to_case(&w1_dash_pair()).unwrap();
        assert_eq!(case.control.tier3_content, vec!["ATTACKER_IBAN_12345".to_string()]);
        assert_eq!(case.probe.tier3_content, case.control.tier3_content, "tier3 fixed across the transform");
        assert_eq!(case.control.tool_name, "send_money");
        // control carries the verbatim value; probe the laundered one.
        let cv = case.control.parameters.get("recipient").and_then(|v| v.as_str()).unwrap();
        let pv = case.probe.parameters.get("recipient").and_then(|v| v.as_str()).unwrap();
        assert_eq!(cv, "ATTACKER_IBAN_12345");
        assert_eq!(pv, "ATTACKER-IBAN-12345");
    }

    #[test]
    fn pair_to_case_relocates_the_key_and_fixes_tier3() {
        let case = pair_to_case(&w2_relocated_pair()).unwrap();
        assert_eq!(case.control.tier3_content, vec!["ATTACKER_IBAN_12345".to_string()]);
        assert_eq!(case.probe.tier3_content, case.control.tier3_content, "tier3 fixed across the relocation");
        // control carries the watched key; probe carries the relocated sibling key,
        // same value.
        assert_eq!(
            case.control.parameters.get("recipient").and_then(|v| v.as_str()),
            Some("ATTACKER_IBAN_12345")
        );
        assert!(case.control.parameters.get("recipient_note").is_none());
        assert_eq!(
            case.probe.parameters.get("recipient_note").and_then(|v| v.as_str()),
            Some("ATTACKER_IBAN_12345")
        );
        assert!(case.probe.parameters.get("recipient").is_none());
    }

    #[test]
    fn params_convert_to_json_faithfully() {
        let mut m = BTreeMap::new();
        m.insert("s".into(), ParamValue::Str("x".into()));
        m.insert("n".into(), ParamValue::Int(3));
        m.insert("b".into(), ParamValue::Bool(true));
        let j = params_to_json(&m);
        assert_eq!(j.get("s").unwrap(), "x");
        assert_eq!(j.get("n").unwrap(), 3);
        assert_eq!(j.get("b").unwrap(), true);
    }

    #[test]
    fn reverify_matches_the_live_outcome() {
        // Offline re-judge from recorded decisions gives the same loop outcome as the
        // live run (the one-oracle guarantee at this seam).
        let pair = w1_dash_pair();
        let live = judge_pair(&VulnerableGate, &pair).unwrap();
        // The vulnerable gate: control escalated, probe approved.
        let offline = reverify("x", GateDecisionView::Escalated, Some(GateDecisionView::Approved));
        assert_eq!(live, offline);
        assert_eq!(live, ProbeOutcome::Fail);
    }
}
