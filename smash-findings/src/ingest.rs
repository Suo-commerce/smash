//! Ingest — projecting real run artifacts into ledger records (step 2).
//!
//! This is the **only** part of `smash-findings` that depends on the rest of the
//! workspace; it is gated behind the `ingest` feature so the pure-data core
//! (`record` / `lifecycle` / `ledger` / `cluster`) compiles and tests with no `smash-*`
//! crate.
//!
//! Two jobs, and one rule:
//! - project a `smash_generator::Candidate` + its `smash_loop::regions::AdmittedRegion`
//!   + the run's `ProbeOutcome` into a [`CandidateRecord`](crate::record::CandidateRecord);
//! - **verify the bundle offline before trusting it** — `verified_bundle_ref` reuses the
//!   engine's pinned oracle (`matchlog::verify`), and an unverifiable bundle yields no
//!   usable `BundleRef`, so its findings can never be promoted. [`ingest_run`] refuses
//!   to ingest *any* record from a bundle that does not verify (fail closed).
//!
//! The rule: ingest records what happened; it never re-judges (the one-oracle
//! guarantee) and never promotes (that stays a human lifecycle decision).
//!
//! ## Honesty enforcements carried in here
//! - **N7 exploratory cap.** An exploratory candidate (unregistered handle, no validated
//!   oracle) can never record a `Kill`; a `Fail` is capped to `Inconclusive` at ingest.
//! - **Fidelity is ResponseOnly by default.** The engine reads a decision from the
//!   response; `EffectConfirmed` requires a fixture state receipt (the §4 stage-5 gap)
//!   the `RunBundle` does not yet carry. A receipt-aware caller passes `EffectConfirmed`
//!   explicitly; absent that, a `Kill` is honestly marked `ResponseOnly`.
//! - **Clustering inputs are trusted, not candidate-asserted.** The [`MechanismId`] is
//!   projected from the candidate's template + provenance; the **evidence signature** is
//!   an oracle-versioned equivalence key over the *verified bundle's* recorded decisions
//!   (autonomous-loop §7). Neither is supplied by the generator — the same posture as
//!   severity. Two encodings of one fault share a signature (same decision pattern +
//!   verdict kind), while a distinct fault does not; per-run evidence strings are
//!   normalized away so the key is an equivalence, not a byte identity.

use crate::record::{
    AdmissionOutcome, BundleRef, CandidateKey, CandidateRecord, EvidenceFidelity, MechanismId,
    ProvenanceRecord, VerdictClass,
};

use smash_engine::differential::GateDecisionView;
use smash_engine::matchlog::{verify, CaseRecord, RunBundle, VerdictRecord, VerifyFailure, VerifyOutcome};
use smash_generator::candidate::{Candidate, Source};
use smash_loop::regions::AdmittedRegion;
use smash_loop::verdict::ProbeOutcome;

use std::fmt;

// ── Projections (pure) ───────────────────────────────────────────────────────

/// Map a loop [`ProbeOutcome`] to the ledger's [`VerdictClass`]. All four are recorded;
/// only `Kill` is promotable (oracle asymmetry), and `Defended` is a coverage fact.
pub fn verdict_class(outcome: &ProbeOutcome) -> VerdictClass {
    match outcome {
        ProbeOutcome::Pass => VerdictClass::Defended,
        ProbeOutcome::Fail => VerdictClass::Kill,
        ProbeOutcome::Error => VerdictClass::Error,
        ProbeOutcome::Inconclusive(_) => VerdictClass::Inconclusive,
    }
}

/// The evidence fidelity derivable from the engine path alone: a decision read from the
/// response is `ResponseOnly`; an inconclusive/error outcome has no fidelity signal.
/// `EffectConfirmed` is never produced here — it requires a state receipt a caller
/// supplies explicitly (see the module docs).
pub fn default_fidelity(outcome: &ProbeOutcome) -> EvidenceFidelity {
    match outcome {
        ProbeOutcome::Pass | ProbeOutcome::Fail => EvidenceFidelity::ResponseOnly,
        _ => EvidenceFidelity::Inconclusive,
    }
}

fn render_template(c: &Candidate) -> String {
    format!("{}/{}", c.template.fighter, c.template.technique)
}

fn render_oracle(c: &Candidate) -> String {
    format!("{}/{}/{}", c.oracle.kind, c.oracle.id, c.oracle.version)
}

fn render_source(s: &Source) -> String {
    match s {
        Source::Seed => "seed".to_string(),
        Source::Mutation { mutator, .. } => format!("mutation:{mutator}"),
        Source::CveAnalog { advisory } => format!("cve:{advisory}"),
        Source::ModelArtifact { hash } => format!("model:{hash}"),
    }
}

/// Project the candidate's mechanism identity (autonomous-loop §7): template from the
/// handle, mutator from the provenance source, transform = the mutator class (a finer
/// transform id can split it later without changing the predicate's shape). Trusted
/// side — derived from the candidate's declaration, never candidate-asserted severity-style.
fn mechanism_of(c: &Candidate) -> MechanismId {
    let (mutator, transform) = match &c.provenance.source {
        Source::Seed => ("seed".to_string(), "seed".to_string()),
        Source::Mutation { mutator, .. } => (mutator.clone(), mutator.clone()),
        Source::CveAnalog { advisory } => (format!("cve:{advisory}"), format!("cve:{advisory}")),
        Source::ModelArtifact { hash } => (format!("model:{hash}"), format!("model:{hash}")),
    };
    MechanismId {
        template: render_template(c),
        mutator,
        transform,
    }
}

fn provenance_record(c: &Candidate) -> ProvenanceRecord {
    ProvenanceRecord {
        generator_id: c.provenance.generator_id.clone(),
        generator_version: c.provenance.generator_version,
        source: render_source(&c.provenance.source),
        seed: c.provenance.seed,
    }
}

/// Project an [`AdmittedRegion`] into the record's admission outcome.
pub fn admitted_outcome(admitted: &AdmittedRegion) -> AdmissionOutcome {
    AdmissionOutcome::Admitted {
        region: admitted.region.0.clone(),
        adequacy_target: admitted.adequacy_target,
        exploratory: admitted.exploratory,
    }
}

// ── Evidence signature (the §7 equivalence key) ───────────────────────────────

fn decision_tag(d: GateDecisionView) -> &'static str {
    match d {
        GateDecisionView::Approved => "approved",
        GateDecisionView::Escalated => "escalated",
        GateDecisionView::Blocked => "blocked",
        GateDecisionView::Intercepted => "intercepted",
    }
}

fn verdict_record_kind(v: &VerdictRecord) -> &'static str {
    match v {
        VerdictRecord::Pass { .. } => "pass",
        VerdictRecord::Fail { .. } => "fail",
        VerdictRecord::Inconclusive { .. } => "inconclusive",
        VerdictRecord::Denied { .. } => "denied",
        VerdictRecord::Error { .. } => "error",
    }
}

/// The oracle-versioned **evidence signature** for a recorded case (autonomous-loop §7):
/// a normalized equivalence key over `(oracle, control decision, probe decision, verdict
/// kind)`. Per-run evidence strings and inputs are deliberately excluded, so two
/// encodings of one fault (same decision pattern) share the key while an adjacent-but-
/// distinct fault (different pattern) does not. Versioned (`sig:v1:`) so a rule change is
/// explainable rather than a silent identity shift.
pub fn evidence_signature(oracle: &str, case: &CaseRecord) -> String {
    let control = decision_tag(case.control_decision);
    let probe = case.probe_decision.map(decision_tag).unwrap_or("none");
    let verdict = verdict_record_kind(&case.verdict);
    format!("sig:v1:{oracle}|{control}|{probe}|{verdict}")
}

// ── Record builders ──────────────────────────────────────────────────────────

fn mirror_identity(c: &Candidate) -> (CandidateKey, String, String, String, String) {
    (
        CandidateKey(c.canonical_key().0),
        render_template(c),
        c.target_handle.clone(),
        c.effect_class.to_string(),
        render_oracle(c),
    )
}

/// Build a record for an **admitted** candidate from one run's outcome. Enforces the
/// N7 exploratory cap (a `Fail` becomes `Inconclusive`), attaches the verified
/// `bundle_ref`, projects the mechanism id + the caller-computed evidence signature (the
/// §7 clustering inputs), and records the candidate's provenance as a variant.
#[allow(clippy::too_many_arguments)]
pub fn record_from_run(
    candidate: &Candidate,
    admitted: &AdmittedRegion,
    outcome: &ProbeOutcome,
    fidelity: EvidenceFidelity,
    bundle_ref: BundleRef,
    evidence_signature: String,
    now_unix: u64,
) -> CandidateRecord {
    let (key, template, target_handle, effect_class, oracle) = mirror_identity(candidate);

    // N7: an exploratory candidate can never record a Kill — cap it.
    let (verdict, fidelity) = match (verdict_class(outcome), admitted.exploratory) {
        (VerdictClass::Kill, true) => (VerdictClass::Inconclusive, EvidenceFidelity::Inconclusive),
        (v, _) => (v, fidelity),
    };

    let mut rec = CandidateRecord::surfaced(
        key,
        template,
        target_handle,
        effect_class,
        oracle,
        admitted_outcome(admitted),
        Some(verdict),
        fidelity,
        now_unix,
    );
    rec.bundle_ref = Some(bundle_ref);
    rec.mechanism = mechanism_of(candidate);
    rec.evidence_signature = evidence_signature;
    rec.provenance_variants.push(provenance_record(candidate));
    rec
}

/// Build a record for a candidate **rejected at admission** (region/oracle admission).
/// It never ran: no verdict, seated at `RejectedAtAdmission` as coverage.
pub fn record_rejected(
    candidate: &Candidate,
    reason: impl Into<String>,
    now_unix: u64,
) -> CandidateRecord {
    not_executed(
        candidate,
        AdmissionOutcome::Rejected { reason: reason.into() },
        now_unix,
    )
}

/// Build a record for a candidate **denied by the capability gate** (scope / authority
/// / expiry / budget). It never ran: no verdict, seated at `RejectedAtAdmission`.
pub fn record_denied(
    candidate: &Candidate,
    reason: impl Into<String>,
    now_unix: u64,
) -> CandidateRecord {
    not_executed(
        candidate,
        AdmissionOutcome::Denied { reason: reason.into() },
        now_unix,
    )
}

fn not_executed(
    candidate: &Candidate,
    admission: AdmissionOutcome,
    now_unix: u64,
) -> CandidateRecord {
    let (key, template, target_handle, effect_class, oracle) = mirror_identity(candidate);
    let mut rec = CandidateRecord::surfaced(
        key,
        template,
        target_handle,
        effect_class,
        oracle,
        admission,
        None,
        EvidenceFidelity::Inconclusive,
        now_unix,
    );
    // A candidate that never ran still carries its mechanism (template + provenance) for
    // coverage; it has no evidence signature (it produced no decisions), so it never
    // clusters — correct, it is not a finding.
    rec.mechanism = mechanism_of(candidate);
    rec.provenance_variants.push(provenance_record(candidate));
    crate::lifecycle::seat_initial(&mut rec, now_unix);
    rec
}

// ── Bundle verification ──────────────────────────────────────────────────────

/// Why ingest refused a bundle.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum IngestError {
    /// The bundle did not verify under the pinned oracle; its findings are
    /// non-reproducible and must not enter the ledger as promotable records.
    Unverifiable(VerifyFailure),
}

impl fmt::Display for IngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IngestError::Unverifiable(why) => {
                write!(f, "bundle does not verify, refusing to ingest: {why:?}")
            }
        }
    }
}

impl std::error::Error for IngestError {}

/// Verify a bundle offline (the engine's pinned oracle, no gate call) and, on success,
/// produce a [`BundleRef`] pinned to the bundle's own content digest. An unverifiable
/// bundle yields no ref — the single choke point that keeps non-reproducible evidence
/// out of the ledger.
pub fn verified_bundle_ref(
    bundle: &RunBundle,
    path: impl Into<String>,
) -> Result<BundleRef, IngestError> {
    match verify(bundle) {
        VerifyOutcome::Verified { .. } => Ok(BundleRef {
            path: path.into(),
            digest: bundle.digest.clone(),
        }),
        VerifyOutcome::Failed(why) => Err(IngestError::Unverifiable(why)),
    }
}

// ── Whole-run ingest ─────────────────────────────────────────────────────────

/// One run's candidate→outcome correspondence (the harness that generated candidate *i*
/// and ran case *i* owns this pairing; the bundle itself does not carry candidate keys).
pub struct RunItem {
    pub candidate: Candidate,
    pub admitted: AdmittedRegion,
    pub outcome: ProbeOutcome,
    /// `EffectConfirmed` when the caller has a state receipt; otherwise leave `None`
    /// and `default_fidelity` is used (ResponseOnly / Inconclusive).
    pub fidelity: Option<EvidenceFidelity>,
}

/// Ingest a whole run into the ledger. **Fails closed**: the bundle is verified first,
/// and if it does not verify, *nothing* is ingested. On success every item is upserted
/// (new row or dedup-merge) and the number of items ingested is returned.
///
/// Each item is paired with its recorded case by index (`bundle.cases[i]`, the same
/// alignment `matchlog::RunBundle::build` produces) to compute the evidence signature. An
/// item with no paired case gets an empty signature — unproven, so it never clusters.
pub fn ingest_run(
    ledger: &mut crate::ledger::Ledger,
    bundle: &RunBundle,
    bundle_path: impl Into<String>,
    items: &[RunItem],
    now_unix: u64,
) -> Result<usize, IngestError> {
    let bref = verified_bundle_ref(bundle, bundle_path)?;
    for (i, item) in items.iter().enumerate() {
        let fidelity = item.fidelity.unwrap_or_else(|| default_fidelity(&item.outcome));
        let signature = match bundle.cases.get(i) {
            Some(case) => evidence_signature(&render_oracle(&item.candidate), case),
            None => String::new(),
        };
        let rec = record_from_run(
            &item.candidate,
            &item.admitted,
            &item.outcome,
            fidelity,
            bref.clone(),
            signature,
            now_unix,
        );
        ledger.upsert(rec);
    }
    Ok(items.len())
}

#[cfg(test)]
mod tests {
    // Note: `smash-findings` does not link `smash_core` (even under `ingest` it pulls
    // only generator/loop/engine), so these tests cannot construct a `Candidate` — that
    // needs core types this crate can't name. The `Candidate`-fed projections
    // (`mechanism_of`, `record_from_run`) are exercised by the item-5 capstone
    // integration; here we test the signature logic, which needs only engine types.
    use super::*;
    use smash_engine::differential::GateInput;

    fn case(
        control: GateDecisionView,
        probe: Option<GateDecisionView>,
        verdict: VerdictRecord,
    ) -> CaseRecord {
        CaseRecord {
            name: "c".into(),
            control_input: GateInput::external_action(
                "send_money",
                serde_json::json!({"recipient": "x"}),
                vec!["x".into()],
            ),
            probe_input: GateInput::external_action(
                "send_money",
                serde_json::json!({"recipient": "y"}),
                vec!["x".into()],
            ),
            control_decision: control,
            probe_decision: probe,
            verdict,
        }
    }

    #[test]
    fn equivalent_decisions_share_a_signature() {
        // Same decision pattern + verdict kind → same signature, even though the Fail's
        // expected/observed/evidence strings differ (those are normalized away).
        let a = case(
            GateDecisionView::Escalated,
            Some(GateDecisionView::Approved),
            VerdictRecord::Fail { expected: "w".into(), observed: "a".into(), evidence: vec![] },
        );
        let b = case(
            GateDecisionView::Escalated,
            Some(GateDecisionView::Approved),
            VerdictRecord::Fail {
                expected: "totally".into(),
                observed: "different".into(),
                evidence: vec!["e".into()],
            },
        );
        assert_eq!(
            evidence_signature("differential/f-b-taint-oracle/v1", &a),
            evidence_signature("differential/f-b-taint-oracle/v1", &b),
        );
    }

    #[test]
    fn a_different_decision_pattern_changes_the_signature() {
        let kill = case(
            GateDecisionView::Escalated,
            Some(GateDecisionView::Approved),
            VerdictRecord::Fail { expected: "w".into(), observed: "a".into(), evidence: vec![] },
        );
        let defended = case(
            GateDecisionView::Escalated,
            Some(GateDecisionView::Escalated),
            VerdictRecord::Pass { evidence: vec![] },
        );
        assert_ne!(
            evidence_signature("o", &kill),
            evidence_signature("o", &defended),
            "a distinct decision pattern must not share a signature (acceptance 8)"
        );
    }
}
