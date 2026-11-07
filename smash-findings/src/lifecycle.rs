//! The lifecycle state machine — the legal-transition graph and its guards (§4).
//!
//! Every state change is a **recorded human decision** (actor, timestamp, rationale),
//! appended to the record's [`Disposition`] history. This module is what makes the
//! candidate≠finding discipline structural: it refuses illegal moves, refuses to
//! ratify a non-promotable candidate, and refuses to mark a candidate a regression
//! fighter without a linked **KILL→DEFENDED bundle pair** proving the gap both existed
//! and is now closed.
//!
//! The ledger (next unit) calls these; the module itself is pure — it mutates a record
//! in memory and returns a typed error, nothing else.
//!
//! ## The graph
//!
//! ```text
//! (not admitted) ─ seat ─► RejectedAtAdmission        terminal; coverage
//!
//! Surfaced ─► Triaged ─►┬─► Rejected{reason}           terminal
//!                       ├─► Duplicate                  terminal
//!                       ├─► AcceptedResidual           terminal
//!                       └─► Ratified ─► Fixtured ─► Fixed ═══(proof)══► Regression   terminal
//! ```
//!
//! `Ratified` requires the candidate be promotable (a non-exploratory `Kill`).
//! `Regression` is reachable only through [`promote_to_regression`], which requires the
//! proof — there is no plain edge into it.

use crate::record::{
    AdmissionOutcome, BundleRef, CandidateRecord, LifecycleState, Transition,
};

/// Why a transition was refused. Each is a fact a caller surfaces; none mutate state.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum TransitionError {
    /// `to` is not a legal successor of the record's current state.
    Illegal {
        from: LifecycleState,
        to: LifecycleState,
    },
    /// The record is already in a terminal state — no transition is legal.
    Terminal { from: LifecycleState },
    /// `Ratified` was attempted on a candidate that cannot become a finding — it did
    /// not produce a non-exploratory `Kill`.
    NotPromotable,
    /// `Regression` was attempted through [`apply_transition`]; it has no plain edge.
    /// Use [`promote_to_regression`], which requires the bundle-pair proof.
    RegressionNeedsProof,
    /// The KILL→DEFENDED proof is invalid: the two bundles must be distinct (a gap
    /// that existed, and a run that shows it closed).
    InvalidRegressionProof,
}

/// A proof that a ratified gap was closed: the pre-fix bundle that recorded the
/// `Kill`, and the post-fix bundle that recorded the `Defended`. Required to promote a
/// candidate to a permanent regression fighter. (The bundles are verified offline by
/// the ingest layer; this module only requires that the pair is present and distinct.)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegressionProof {
    pub kill_bundle: BundleRef,
    pub defended_bundle: BundleRef,
}

impl RegressionProof {
    /// A proof is well-formed only if its two bundles are distinct — the same bundle
    /// cannot both show the gap and show it closed.
    pub fn is_distinct(&self) -> bool {
        self.kill_bundle != self.defended_bundle
    }
}

/// The initial lifecycle state implied by a candidate's admission outcome: an admitted
/// candidate starts `Surfaced`; a rejected/denied one starts `RejectedAtAdmission`
/// (terminal coverage, never triaged, never a finding).
pub fn initial_state(admission: &AdmissionOutcome) -> LifecycleState {
    if admission.was_admitted() {
        LifecycleState::Surfaced
    } else {
        LifecycleState::RejectedAtAdmission
    }
}

/// Seat a freshly-built record in its correct initial state. A record is created with
/// an empty history (whose current state reads as `Surfaced`); for a non-admitted
/// candidate this seats the single `system` transition to `RejectedAtAdmission` so its
/// current state is correct. Idempotent on an already-seated record.
pub fn seat_initial(record: &mut CandidateRecord, now_unix: u64) {
    if !record.disposition.history.is_empty() {
        return;
    }
    if !record.admission.was_admitted() {
        record.disposition.history.push(Transition::new(
            LifecycleState::RejectedAtAdmission,
            "system",
            now_unix,
            "rejected/denied at admission — recorded as coverage",
        ));
    }
}

/// Whether `to` is a legal successor of `from` by a plain edge. (The `Fixed →
/// Regression` edge is *not* here — it goes through [`promote_to_regression`] because
/// it needs the proof. `RejectedAtAdmission` is an initial state, not a target.)
pub fn is_legal_transition(from: &LifecycleState, to: &LifecycleState) -> bool {
    use LifecycleState::*;
    matches!(
        (from, to),
        (Surfaced, Triaged)
            | (Triaged, Rejected { .. })
            | (Triaged, Duplicate)
            | (Triaged, AcceptedResidual)
            | (Triaged, Ratified)
            | (Ratified, Fixtured)
            | (Fixtured, Fixed)
    )
}

/// Apply a lifecycle transition, recording it as a human decision. Rejects illegal
/// edges, transitions out of a terminal state, ratifying a non-promotable candidate,
/// and any attempt to reach `Regression` without the proof. On success the transition
/// is appended and the record's current state advances.
pub fn apply_transition(
    record: &mut CandidateRecord,
    to: LifecycleState,
    actor: impl Into<String>,
    now_unix: u64,
    rationale: impl Into<String>,
) -> Result<(), TransitionError> {
    let from = record.state();

    // Regression has no plain edge — it requires the bundle-pair proof.
    if matches!(to, LifecycleState::Regression) {
        return Err(TransitionError::RegressionNeedsProof);
    }
    // RejectedAtAdmission is an initial state, never a transition target.
    if matches!(to, LifecycleState::RejectedAtAdmission) {
        return Err(TransitionError::Illegal { from, to });
    }
    if from.is_terminal() {
        return Err(TransitionError::Terminal { from });
    }
    if !is_legal_transition(&from, &to) {
        return Err(TransitionError::Illegal { from, to });
    }
    // Ratification is reserved for a candidate that can actually become a finding.
    if matches!(to, LifecycleState::Ratified) && !record.is_promotable() {
        return Err(TransitionError::NotPromotable);
    }

    record
        .disposition
        .history
        .push(Transition::new(to, actor, now_unix, rationale));
    Ok(())
}

/// Promote a `Fixed` candidate to a permanent regression fighter. Requires a distinct
/// KILL→DEFENDED bundle pair — the one place the lifecycle "refuses to lie": a
/// regression is admitted only once there is reproducible evidence the gap existed and
/// a later run that shows it closed.
pub fn promote_to_regression(
    record: &mut CandidateRecord,
    proof: RegressionProof,
    actor: impl Into<String>,
    now_unix: u64,
    rationale: impl Into<String>,
) -> Result<(), TransitionError> {
    let from = record.state();
    if from.is_terminal() {
        return Err(TransitionError::Terminal { from });
    }
    if !matches!(from, LifecycleState::Fixed) {
        return Err(TransitionError::Illegal {
            from,
            to: LifecycleState::Regression,
        });
    }
    if !proof.is_distinct() {
        return Err(TransitionError::InvalidRegressionProof);
    }

    record.disposition.history.push(Transition::new(
        LifecycleState::Regression,
        actor,
        now_unix,
        rationale,
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{
        AdmissionOutcome, CandidateKey, CandidateRecord, EvidenceFidelity, LifecycleState,
        RejectReason, VerdictClass,
    };

    fn kill_record() -> CandidateRecord {
        CandidateRecord::surfaced(
            CandidateKey("k".into()),
            "taint-launder/encoding-equiv",
            "send_money.recipient",
            "mutating",
            "differential/f-b-taint-oracle/v1",
            AdmissionOutcome::Admitted {
                region: "encodings".into(),
                adequacy_target: 8,
                exploratory: false,
            },
            Some(VerdictClass::Kill),
            EvidenceFidelity::EffectConfirmed,
            1_700_000_000,
        )
    }

    fn bundle(tag: &str) -> BundleRef {
        BundleRef {
            path: format!("smash-runs/{tag}.json"),
            digest: format!("{tag}-digest"),
        }
    }

    fn step(
        r: &mut CandidateRecord,
        to: LifecycleState,
    ) -> Result<(), TransitionError> {
        apply_transition(r, to, "jarmo", 1_700_000_100, "test")
    }

    #[test]
    fn full_happy_path_to_regression() {
        let mut r = kill_record();
        step(&mut r, LifecycleState::Triaged).unwrap();
        step(&mut r, LifecycleState::Ratified).unwrap();
        step(&mut r, LifecycleState::Fixtured).unwrap();
        step(&mut r, LifecycleState::Fixed).unwrap();
        promote_to_regression(
            &mut r,
            RegressionProof {
                kill_bundle: bundle("pre-fix"),
                defended_bundle: bundle("post-fix"),
            },
            "jarmo",
            1_700_000_500,
            "fix lands; KILL→DEFENDED confirmed",
        )
        .unwrap();
        assert_eq!(r.state(), LifecycleState::Regression);
        assert!(r.state().is_terminal());
        assert_eq!(r.disposition.history.len(), 5);
    }

    #[test]
    fn surfaced_cannot_jump_to_regression() {
        let mut r = kill_record();
        assert_eq!(
            step(&mut r, LifecycleState::Regression),
            Err(TransitionError::RegressionNeedsProof)
        );
    }

    #[test]
    fn surfaced_cannot_skip_triage_to_ratified() {
        let mut r = kill_record();
        assert!(matches!(
            step(&mut r, LifecycleState::Ratified),
            Err(TransitionError::Illegal { .. })
        ));
    }

    #[test]
    fn a_defended_candidate_cannot_be_ratified() {
        let mut r = kill_record();
        r.verdict = Some(VerdictClass::Defended);
        step(&mut r, LifecycleState::Triaged).unwrap();
        assert_eq!(
            step(&mut r, LifecycleState::Ratified),
            Err(TransitionError::NotPromotable)
        );
    }

    #[test]
    fn an_exploratory_kill_cannot_be_ratified() {
        let mut r = kill_record();
        r.admission = AdmissionOutcome::Admitted {
            region: "encodings".into(),
            adequacy_target: 8,
            exploratory: true,
        };
        step(&mut r, LifecycleState::Triaged).unwrap();
        assert_eq!(
            step(&mut r, LifecycleState::Ratified),
            Err(TransitionError::NotPromotable)
        );
    }

    #[test]
    fn regression_needs_a_distinct_bundle_pair() {
        let mut r = kill_record();
        step(&mut r, LifecycleState::Triaged).unwrap();
        step(&mut r, LifecycleState::Ratified).unwrap();
        step(&mut r, LifecycleState::Fixtured).unwrap();
        step(&mut r, LifecycleState::Fixed).unwrap();
        let same = bundle("same");
        assert_eq!(
            promote_to_regression(
                &mut r,
                RegressionProof { kill_bundle: same.clone(), defended_bundle: same },
                "jarmo",
                1,
                "oops same bundle",
            ),
            Err(TransitionError::InvalidRegressionProof)
        );
    }

    #[test]
    fn cannot_promote_to_regression_before_fixed() {
        let mut r = kill_record();
        step(&mut r, LifecycleState::Triaged).unwrap();
        step(&mut r, LifecycleState::Ratified).unwrap();
        // still only Ratified, not Fixed
        assert!(matches!(
            promote_to_regression(
                &mut r,
                RegressionProof { kill_bundle: bundle("a"), defended_bundle: bundle("b") },
                "jarmo",
                1,
                "too early",
            ),
            Err(TransitionError::Illegal { .. })
        ));
    }

    #[test]
    fn terminal_states_refuse_further_transitions() {
        let mut r = kill_record();
        step(&mut r, LifecycleState::Triaged).unwrap();
        step(&mut r, LifecycleState::Rejected { reason: RejectReason::ByDesign }).unwrap();
        assert!(r.state().is_terminal());
        assert!(matches!(
            step(&mut r, LifecycleState::Fixtured),
            Err(TransitionError::Terminal { .. })
        ));
    }

    #[test]
    fn triage_can_branch_to_accepted_residual() {
        // The Aegloss unauthenticated-ingest race: a known, accepted residual.
        let mut r = kill_record();
        step(&mut r, LifecycleState::Triaged).unwrap();
        step(&mut r, LifecycleState::AcceptedResidual).unwrap();
        assert_eq!(r.state(), LifecycleState::AcceptedResidual);
        assert!(r.state().is_terminal());
    }

    #[test]
    fn non_admitted_record_seats_at_rejected_at_admission() {
        let mut r = CandidateRecord::surfaced(
            CandidateKey("k".into()),
            "f/t",
            "tool.param",
            "mutating",
            "differential/o/v1",
            AdmissionOutcome::Rejected { reason: "param out of bounds".into() },
            None,
            EvidenceFidelity::Inconclusive,
            1_700_000_000,
        );
        assert_eq!(r.state(), LifecycleState::Surfaced, "empty history reads Surfaced");
        seat_initial(&mut r, 1_700_000_000);
        assert_eq!(r.state(), LifecycleState::RejectedAtAdmission);
        assert!(r.state().is_terminal());
        // and no further transitions
        assert!(matches!(
            step(&mut r, LifecycleState::Triaged),
            Err(TransitionError::Terminal { .. })
        ));
    }

    #[test]
    fn seat_initial_is_noop_for_admitted_and_idempotent() {
        let mut r = kill_record();
        seat_initial(&mut r, 1);
        assert_eq!(r.state(), LifecycleState::Surfaced);
        assert!(r.disposition.history.is_empty());
        // idempotent after real transitions
        step(&mut r, LifecycleState::Triaged).unwrap();
        let before = r.disposition.history.len();
        seat_initial(&mut r, 1);
        assert_eq!(r.disposition.history.len(), before);
    }
}
