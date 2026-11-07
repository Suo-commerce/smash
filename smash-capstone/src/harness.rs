//! A concrete differential-discovery harness — the real loop ports that drive the
//! model-free generator's metamorphic pairs through an in-process gate differential.
//! This is the bridge the P3 §10 capstone (and any in-process differential target)
//! wires into [`smash_loop::run::DiscoveryRun`].
//!
//! ## The impedance it bridges
//!
//! `DiscoveryRun` dispatches **one `PlanEntry` at a time** and gets back a
//! [`ProbeOutcome`]; the differential oracle (`smash_loop::metamorphic::judge_pair`) needs
//! the **control + probe pair**. The bridge is a shared **pair-book**:
//!
//! - [`MetamorphicGenerator`] runs `generate_pairs`, and for each pair's *variant*
//!   (the probe) it computes the **same recomputed candidate key** admission will
//!   (`smash_engine::candidate_key`, from the handle + validated params), inserts the
//!   pair into the book under that key, and emits a [`CandidateProposal`].
//! - [`DifferentialDispatcher`] holds the gate + the same book; on a probe dispatch it
//!   looks the pair up by the entry's key, runs the differential, records the
//!   `(case, result)` for later bundling, and maps the verdict to a `ProbeOutcome`.
//!
//! Generator and dispatcher are separate port objects the controller owns, so they
//! share the book through an `Rc<RefCell<_>>` (the loop is single-threaded). Because the
//! generator keys the book with exactly the key admission recomputes, the dispatcher's
//! lookup always hits for an admitted probe.

use smash_core::verdict::Verdict;
use smash_engine::candidate_key::candidate_key;
use smash_engine::differential::{run_case, DifferentialCase, DifferentialResult, Gate};
use smash_engine::registry::TechniqueHandle;
use smash_generator::candidate::Candidate;
use smash_generator::mutators::Mutator;
use smash_generator::search::{generate_pairs, MetamorphicPair, SearchConfig};
use smash_loop::epoch::DispatchContext;
use smash_loop::feedback::TypedFeedback;
use smash_loop::metamorphic::{pair_to_case, params_to_json};
use smash_loop::plan::PlanEntry;
use smash_loop::ports::{CandidateProposal, Dispatcher, Generator, Oracle};
use smash_loop::verdict::{InconclusiveReason, ProbeOutcome};
use smash_loop::{CanonicalKey, RegionId};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

/// The shared map from a probe's **recomputed** candidate key to the metamorphic pair it
/// came from. Written by the generator, read by the dispatcher; shared by `Rc` clone.
pub type PairBook = Rc<RefCell<BTreeMap<CanonicalKey, MetamorphicPair>>>;

/// A fresh, empty pair-book to hand to a generator/dispatcher pair.
pub fn new_pair_book() -> PairBook {
    Rc::new(RefCell::new(BTreeMap::new()))
}

/// Map an engine [`Verdict`] to a loop [`ProbeOutcome`], matching
/// `smash_loop::metamorphic`'s projection: `Inconclusive` carries `AmbiguousRouting`, and
/// a `Denied`/unknown variant (not a judged probe) is an `UnexpectedRejection`.
fn outcome_of(v: &Verdict) -> ProbeOutcome {
    ProbeOutcome::from_verdict(v, Some(InconclusiveReason::AmbiguousRouting)).unwrap_or(
        ProbeOutcome::Inconclusive(InconclusiveReason::UnexpectedRejection),
    )
}

/// The real [`Generator`] for in-process differential discovery: seeds + reviewed
/// mutators → metamorphic pairs → one [`CandidateProposal`] per variant, with the pair
/// booked under the variant's recomputed key. Open-loop (it proposes its whole batch
/// once, then nothing); `adjust` is a no-op until feedback-guided search is added.
///
/// Every variant is assigned the one `region`; richer region assignment (by transform
/// class) is a later refinement that does not change this bridge.
pub struct MetamorphicGenerator {
    mutators: Vec<Box<dyn Mutator>>,
    seeds: Vec<Candidate>,
    config: SearchConfig,
    region: RegionId,
    book: PairBook,
    done: bool,
}

impl MetamorphicGenerator {
    pub fn new(
        mutators: Vec<Box<dyn Mutator>>,
        seeds: Vec<Candidate>,
        config: SearchConfig,
        region: RegionId,
        book: PairBook,
    ) -> Self {
        MetamorphicGenerator {
            mutators,
            seeds,
            config,
            region,
            book,
            done: false,
        }
    }

    /// The recomputed candidate key for a variant — identical to what admission computes
    /// (`smash_engine::candidate_key` over the handle + lowered params), so the
    /// dispatcher's book lookup hits for an admitted probe.
    pub fn variant_key(variant: &Candidate) -> CanonicalKey {
        let params_json = params_to_json(&variant.params);
        CanonicalKey(candidate_key(
            variant.template.fighter.as_str(),
            variant.template.technique.as_str(),
            &params_json,
        ))
    }
}

impl Generator for MetamorphicGenerator {
    fn propose(&mut self) -> Vec<CandidateProposal> {
        if self.done {
            return Vec::new();
        }
        self.done = true;

        let pairs = generate_pairs(&self.mutators, &self.seeds, &self.config);
        let mut proposals = Vec::with_capacity(pairs.len());
        for pair in pairs {
            let variant = &pair.variant;
            let key = Self::variant_key(variant);
            let handle = TechniqueHandle::new(
                variant.template.fighter.clone(),
                variant.template.technique.clone(),
            );
            self.book.borrow_mut().insert(key.clone(), pair.clone());
            proposals.push(CandidateProposal {
                key,
                handle,
                intended_region: self.region.clone(),
                params: variant.params.clone(),
            });
        }
        proposals
    }

    fn adjust(&mut self, _feedback: &TypedFeedback) {}
}

/// The real [`Dispatcher`] for in-process differential discovery: looks the probe's pair
/// up in the shared book and runs the differential against the gate. Records every
/// `(case, result)` so the harness can assemble a `RunBundle` for the findings ledger.
/// A control entry is a benign support dispatch (the differential's own control is
/// internal to the case), so it resolves `Pass` and is never a finding.
pub struct DifferentialDispatcher<G: Gate> {
    gate: G,
    book: PairBook,
    results: Rc<RefCell<Vec<(DifferentialCase, DifferentialResult)>>>,
}

impl<G: Gate> DifferentialDispatcher<G> {
    pub fn new(gate: G, book: PairBook) -> Self {
        DifferentialDispatcher {
            gate,
            book,
            results: Rc::new(RefCell::new(Vec::new())),
        }
    }

    /// The recorded `(case, result)` log — the input to a `RunBundle` for ingest.
    pub fn results(&self) -> Rc<RefCell<Vec<(DifferentialCase, DifferentialResult)>>> {
        self.results.clone()
    }
}

impl<G: Gate> Dispatcher for DifferentialDispatcher<G> {
    fn execute(&mut self, entry: &PlanEntry, _ctx: &DispatchContext) -> ProbeOutcome {
        let key = match entry {
            PlanEntry::Probe { key, .. } => key.clone(),
            // A control dispatch is a benign support call; the differential's own control
            // lives inside the probe's case, so this never produces a finding.
            PlanEntry::Control { .. } => return ProbeOutcome::Pass,
        };

        let pair = self.book.borrow().get(&key).cloned();
        let Some(pair) = pair else {
            // No pair for this key — a book/admission mismatch, not a judged probe.
            return ProbeOutcome::Inconclusive(InconclusiveReason::UncorrelatedReceipt);
        };
        let Some(case) = pair_to_case(&pair) else {
            // A malformed pair (no differing string param) — not judgeable.
            return ProbeOutcome::Inconclusive(InconclusiveReason::UnexpectedRejection);
        };

        let result = run_case(&self.gate, &case);
        let outcome = outcome_of(&result.verdict);
        self.results.borrow_mut().push((case, result));
        outcome
    }
}

/// The passthrough [`Oracle`]: the differential already judged inside the dispatcher, so
/// the oracle returns the raw outcome unchanged. (The one-oracle guarantee holds — the
/// single verdict rule is `differential::judge`, invoked via `run_case` in the
/// dispatcher; this does not add a second one.)
pub struct PassthroughOracle;

impl Oracle for PassthroughOracle {
    fn judge(&self, _entry: &PlanEntry, raw: ProbeOutcome) -> ProbeOutcome {
        raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use smash_core::capability::{Authority, RunId};
    use smash_core::correlation::SessionId;
    use smash_core::fighter::{FighterId, OracleId, OracleKind, OracleVersion, TechniqueName};
    use smash_engine::differential::{GateDecisionView, GateInput};
    use smash_generator::candidate::{OracleBinding, ParamValue, Provenance, Source, TemplateRef};
    use smash_generator::mutators::builtin_mutators;
    use smash_loop::epoch::{EpochAllocator, Role};
    use smash_loop::plan::{ControlScope, ProbeKind};
    use std::collections::BTreeMap;

    // ── Faithful fakes (the W1 substring gate), as in the engine's own tests ──
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
            let Some(obj) = input.parameters.as_object() else {
                return GateDecisionView::Approved;
            };
            for (key, val) in obj {
                if !SENSITIVE_KEYS.contains(&key.to_lowercase().as_str()) {
                    continue;
                }
                let mut leaves = Vec::new();
                string_leaves(val, &mut leaves);
                for leaf in &leaves {
                    let v = leaf.to_lowercase();
                    if input
                        .tier3_content
                        .iter()
                        .any(|t| t.to_lowercase().contains(&v))
                    {
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
            let Some(obj) = input.parameters.as_object() else {
                return GateDecisionView::Approved;
            };
            for (key, val) in obj {
                let kl = key.to_lowercase();
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
        params.insert(
            "recipient".into(),
            ParamValue::Str("ATTACKER_IBAN_12345".into()),
        );
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

    fn generator(book: PairBook) -> MetamorphicGenerator {
        MetamorphicGenerator::new(
            builtin_mutators(),
            vec![w1_seed()],
            SearchConfig {
                seed: 7,
                batch_max: 0,
            },
            RegionId("encodings".into()),
            book,
        )
    }

    fn ctx() -> DispatchContext {
        EpochAllocator::new(7, RunId::new("run-1"), SessionId::new("sess-1"))
            .allocate_context(Role::Probe)
    }

    fn dash_proposal(proposals: &[CandidateProposal]) -> &CandidateProposal {
        proposals
            .iter()
            .find(|p| {
                matches!(
                    p.params.get("recipient"),
                    Some(ParamValue::Str(s)) if s == "ATTACKER-IBAN-12345"
                )
            })
            .expect("the dash-laundered variant must be proposed")
    }

    fn probe_entry(key: CanonicalKey) -> PlanEntry {
        PlanEntry::Probe {
            key,
            region: RegionId("encodings".into()),
            kind: ProbeKind::Baseline,
            cost: 1,
        }
    }

    #[test]
    fn generator_proposes_variants_and_books_their_pairs() {
        let book = new_pair_book();
        let mut g = generator(book.clone());
        let proposals = g.propose();
        assert!(!proposals.is_empty());
        let dash = dash_proposal(&proposals);
        assert!(book.borrow().contains_key(&dash.key));
        assert_eq!(
            dash.key,
            MetamorphicGenerator::variant_key(&book.borrow()[&dash.key].variant)
        );
        assert!(
            g.propose().is_empty(),
            "open-loop: a second propose yields nothing"
        );
    }

    #[test]
    fn dispatcher_kills_the_laundered_variant_on_the_vulnerable_gate() {
        let book = new_pair_book();
        let mut g = generator(book.clone());
        let proposals = g.propose();
        let key = dash_proposal(&proposals).key.clone();

        let mut d = DifferentialDispatcher::new(VulnerableGate, book.clone());
        let outcome = d.execute(&probe_entry(key), &ctx());
        assert_eq!(
            outcome,
            ProbeOutcome::Fail,
            "the laundered variant slips the vulnerable gate → KILL"
        );
        assert_eq!(
            d.results().borrow().len(),
            1,
            "the case/result is recorded for bundling"
        );
    }

    #[test]
    fn dispatcher_defends_the_laundered_variant_on_the_fixed_gate() {
        let book = new_pair_book();
        let mut g = generator(book.clone());
        let proposals = g.propose();
        let key = dash_proposal(&proposals).key.clone();

        let mut d = DifferentialDispatcher::new(FixedGate, book.clone());
        assert_eq!(
            d.execute(&probe_entry(key), &ctx()),
            ProbeOutcome::Pass,
            "provenance-by-default withholds it → DEFENDED"
        );
    }

    #[test]
    fn an_unbooked_key_is_inconclusive_not_a_panic() {
        let book = new_pair_book();
        let mut d = DifferentialDispatcher::new(VulnerableGate, book);
        let outcome = d.execute(&probe_entry(CanonicalKey("ghost".into())), &ctx());
        assert_eq!(
            outcome,
            ProbeOutcome::Inconclusive(InconclusiveReason::UncorrelatedReceipt)
        );
    }

    #[test]
    fn a_control_entry_is_a_benign_pass() {
        let book = new_pair_book();
        let mut d = DifferentialDispatcher::new(VulnerableGate, book);
        let control = PlanEntry::Control {
            scope: ControlScope::PerProbe,
            backs: Some(CanonicalKey("c".into())),
            role: Role::WriteControl,
            cost: 1,
        };
        assert_eq!(d.execute(&control, &ctx()), ProbeOutcome::Pass);
    }

    #[test]
    fn passthrough_oracle_returns_the_raw_outcome() {
        let o = PassthroughOracle;
        let entry = probe_entry(CanonicalKey("k".into()));
        assert_eq!(o.judge(&entry, ProbeOutcome::Fail), ProbeOutcome::Fail);
    }
}
