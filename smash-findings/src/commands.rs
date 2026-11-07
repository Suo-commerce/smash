//! The command surface — the human verbs over the ledger (§8).
//!
//! The ledger, the lifecycle state machine, and the reports are all built; this module
//! is the thin verb layer that ties them together and records a human's decision. It is
//! pure data — it mutates a loaded ledger and returns a typed error, nothing more.
//!
//! The verbs:
//! - **disposition** — apply a human triage decision to a stored candidate (triage,
//!   ratify, fixture, fix, reject, duplicate, accept-residual), recorded with
//!   actor/when/why.
//! - **promote** — `Fixed → Regression` with the KILL→DEFENDED bundle pair (the one
//!   place the lifecycle refuses to lie).
//! - the read verbs — `triage` ([`crate::triage::triage`]) and `cover`
//!   ([`crate::coverage::CoverageLedger::report`]) — and `ingest`
//!   ([`crate::ingest`], feature-gated) — already exist; this module adds the mutations
//!   and a [`Store`] that loads and saves both ledgers together.

use crate::coverage::CoverageLedger;
use crate::ledger::Ledger;
use crate::lifecycle::{apply_transition, promote_to_regression, RegressionProof, TransitionError};
use crate::record::{CandidateKey, LifecycleState, RejectReason};
use std::fmt;
use std::io;
use std::path::Path;

/// A human triage decision — the disposition verbs, mapped to lifecycle targets.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    /// Move a surfaced candidate into triage (cluster + confirm).
    Triage,
    /// Ratify the invariant — make it a finding (requires a promotable candidate).
    Ratify,
    /// Record that a seeded failing fixture exists.
    Fixture,
    /// Record that the fix was applied.
    Fix,
    /// Not a real finding, with a reason.
    Reject(RejectReason),
    /// Merge into another candidate/cluster.
    Duplicate,
    /// A known, accepted residual.
    AcceptResidual,
}

impl Decision {
    fn target_state(self) -> LifecycleState {
        match self {
            Decision::Triage => LifecycleState::Triaged,
            Decision::Ratify => LifecycleState::Ratified,
            Decision::Fixture => LifecycleState::Fixtured,
            Decision::Fix => LifecycleState::Fixed,
            Decision::Reject(reason) => LifecycleState::Rejected { reason },
            Decision::Duplicate => LifecycleState::Duplicate,
            Decision::AcceptResidual => LifecycleState::AcceptedResidual,
        }
    }
}

/// Why a command failed.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum CommandError {
    /// No candidate with that key is in the ledger.
    NotFound(CandidateKey),
    /// The lifecycle refused the transition (illegal edge, terminal, not promotable,
    /// missing/invalid regression proof).
    Transition(TransitionError),
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandError::NotFound(k) => write!(f, "no candidate in the ledger for key {:?}", k.0),
            CommandError::Transition(e) => write!(f, "lifecycle refused: {e:?}"),
        }
    }
}

impl std::error::Error for CommandError {}

/// Apply a human disposition to a stored candidate, recorded with actor/when/why.
pub fn disposition(
    ledger: &mut Ledger,
    key: &CandidateKey,
    decision: Decision,
    actor: impl Into<String>,
    now_unix: u64,
    why: impl Into<String>,
) -> Result<(), CommandError> {
    let record = ledger
        .get_mut(key)
        .ok_or_else(|| CommandError::NotFound(key.clone()))?;
    apply_transition(record, decision.target_state(), actor, now_unix, why)
        .map_err(CommandError::Transition)
}

/// Promote a `Fixed` candidate to a permanent regression fighter with the
/// KILL→DEFENDED bundle pair. Refuses without a distinct pair (via the lifecycle).
pub fn promote(
    ledger: &mut Ledger,
    key: &CandidateKey,
    proof: RegressionProof,
    actor: impl Into<String>,
    now_unix: u64,
    why: impl Into<String>,
) -> Result<(), CommandError> {
    let record = ledger
        .get_mut(key)
        .ok_or_else(|| CommandError::NotFound(key.clone()))?;
    promote_to_regression(record, proof, actor, now_unix, why).map_err(CommandError::Transition)
}

/// Both ledgers together — the candidate/finding ledger and the coverage ledger —
/// loaded from and saved to a directory as `candidates.jsonl` and `coverage.jsonl`.
#[derive(Clone, Debug, Default)]
pub struct Store {
    pub candidates: Ledger,
    pub coverage: CoverageLedger,
}

impl Store {
    pub fn new() -> Self {
        Store::default()
    }

    /// Load both ledgers from `dir`. A missing file is an empty ledger (a fresh store);
    /// a present-but-malformed file is an error (fail closed — never silently empty).
    pub fn load(dir: &Path) -> io::Result<Store> {
        let candidates = load_or_empty(&dir.join("candidates.jsonl"), Ledger::read_jsonl, Ledger::new)?;
        let coverage = load_or_empty(
            &dir.join("coverage.jsonl"),
            CoverageLedger::read_jsonl,
            CoverageLedger::new,
        )?;
        Ok(Store { candidates, coverage })
    }

    /// Save both ledgers under `dir`, creating it if needed.
    pub fn save(&self, dir: &Path) -> io::Result<()> {
        std::fs::create_dir_all(dir)?;
        self.candidates.write_jsonl(&dir.join("candidates.jsonl"))?;
        self.coverage.write_jsonl(&dir.join("coverage.jsonl"))?;
        Ok(())
    }
}

/// Read a ledger, treating a missing file as the empty ledger but propagating any other
/// IO/parse error (a malformed ledger is never silently dropped).
fn load_or_empty<T, R, E>(path: &Path, reader: R, empty: E) -> io::Result<T>
where
    R: Fn(&Path) -> io::Result<T>,
    E: Fn() -> T,
{
    match reader(path) {
        Ok(v) => Ok(v),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(empty()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::RegressionProof;
    use crate::record::{
        AdmissionOutcome, BundleRef, CandidateRecord, EvidenceFidelity, VerdictClass,
    };

    fn kill(key: &str) -> CandidateRecord {
        CandidateRecord::surfaced(
            CandidateKey(key.into()),
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
        BundleRef { path: format!("{tag}.json"), digest: format!("{tag}-d") }
    }

    fn ledger_with(key: &str) -> Ledger {
        let mut l = Ledger::new();
        l.upsert(kill(key));
        l
    }

    #[test]
    fn disposition_walks_the_lifecycle_through_commands() {
        let mut l = ledger_with("k");
        let k = CandidateKey("k".into());
        disposition(&mut l, &k, Decision::Triage, "jarmo", 1, "clustered").unwrap();
        disposition(&mut l, &k, Decision::Ratify, "jarmo", 2, "invariant holds").unwrap();
        disposition(&mut l, &k, Decision::Fixture, "jarmo", 3, "seeded").unwrap();
        disposition(&mut l, &k, Decision::Fix, "jarmo", 4, "patched").unwrap();
        assert_eq!(l.get(&k).unwrap().state(), LifecycleState::Fixed);

        promote(
            &mut l,
            &k,
            RegressionProof { kill_bundle: bundle("pre"), defended_bundle: bundle("post") },
            "jarmo",
            5,
            "KILL→DEFENDED confirmed",
        )
        .unwrap();
        assert_eq!(l.get(&k).unwrap().state(), LifecycleState::Regression);
        assert_eq!(l.get(&k).unwrap().disposition.history.len(), 5);
    }

    #[test]
    fn disposition_on_missing_key_is_not_found() {
        let mut l = Ledger::new();
        let err = disposition(&mut l, &CandidateKey("ghost".into()), Decision::Triage, "j", 1, "x").unwrap_err();
        assert!(matches!(err, CommandError::NotFound(_)));
    }

    #[test]
    fn illegal_disposition_surfaces_as_transition_error() {
        let mut l = ledger_with("k");
        let k = CandidateKey("k".into());
        // Surfaced → Ratify is illegal (must triage first).
        let err = disposition(&mut l, &k, Decision::Ratify, "j", 1, "too soon").unwrap_err();
        assert!(matches!(err, CommandError::Transition(_)));
    }

    #[test]
    fn promote_before_fixed_is_refused() {
        let mut l = ledger_with("k");
        let k = CandidateKey("k".into());
        disposition(&mut l, &k, Decision::Triage, "j", 1, "t").unwrap();
        disposition(&mut l, &k, Decision::Ratify, "j", 2, "r").unwrap();
        let err = promote(
            &mut l,
            &k,
            RegressionProof { kill_bundle: bundle("a"), defended_bundle: bundle("b") },
            "j",
            3,
            "too early",
        )
        .unwrap_err();
        assert!(matches!(err, CommandError::Transition(TransitionError::Illegal { .. })));
    }

    #[test]
    fn reject_and_accept_residual_are_terminal_dispositions() {
        let mut l = ledger_with("k");
        let k = CandidateKey("k".into());
        disposition(&mut l, &k, Decision::Triage, "j", 1, "t").unwrap();
        disposition(&mut l, &k, Decision::AcceptResidual, "j", 2, "ingest race, accepted").unwrap();
        assert_eq!(l.get(&k).unwrap().state(), LifecycleState::AcceptedResidual);
        // further disposition refused (terminal)
        assert!(matches!(
            disposition(&mut l, &k, Decision::Ratify, "j", 3, "no"),
            Err(CommandError::Transition(TransitionError::Terminal { .. }))
        ));
    }

    #[test]
    fn store_round_trips_both_ledgers() {
        use crate::coverage::{CoverageFact, CoverageKey, CoverageStatus};
        let mut store = Store::new();
        store.candidates.upsert(kill("k"));
        store.coverage.upsert(CoverageFact {
            key: CoverageKey { target: "aegloss".into(), technique: "approve/decision".into(), region: "r1".into() },
            status: CoverageStatus::Sampled,
            sample_resolved: true,
            summary_cause: None,
            planner_denials: 0,
            throttled: false,
            attempts: 8,
            adequacy_target: 8,
        });

        let dir = std::env::temp_dir().join(format!("smash-store-{}", std::process::id()));
        store.save(&dir).unwrap();
        let back = Store::load(&dir).unwrap();
        assert_eq!(back.candidates.len(), 1);
        assert_eq!(back.coverage.len(), 1);
        assert!(back.coverage.report()[0].complete);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn loading_a_fresh_dir_is_an_empty_store_not_an_error() {
        let dir = std::env::temp_dir().join(format!("smash-store-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::load(&dir).unwrap();
        assert!(store.candidates.is_empty());
        assert!(store.coverage.is_empty());
    }

    #[test]
    fn save_then_disposition_then_save_persists_the_decision() {
        let dir = std::env::temp_dir().join(format!("smash-store-persist-{}", std::process::id()));
        let mut store = Store::new();
        store.candidates.upsert(kill("k"));
        store.save(&dir).unwrap();

        let mut reloaded = Store::load(&dir).unwrap();
        disposition(&mut reloaded.candidates, &CandidateKey("k".into()), Decision::Triage, "j", 1, "t").unwrap();
        reloaded.save(&dir).unwrap();

        let again = Store::load(&dir).unwrap();
        assert_eq!(again.candidates.get(&CandidateKey("k".into())).unwrap().state(), LifecycleState::Triaged);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
