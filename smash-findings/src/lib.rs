//! # smash-findings — the candidate/finding lifecycle ledger
//!
//! As discovery scales — more targets, more reviewed mutators, more runs — the
//! candidate stream outgrows a per-target markdown file. This crate is the durable
//! ledger that organizes it so triage stays tractable and the human stays the one
//! who promotes (`specs/findings-management.md`).
//!
//! ## The one idea: a record, never a referee
//!
//! The ledger **invents no new trust**. It records what admission and the one oracle
//! already produce, links the pinned evidence they already write, and stores the
//! human decisions that were always required. It never computes a verdict, never
//! promotes a candidate, never widens scope, never runs anything. A corrupted or
//! adversarial ledger can mislead *triage*, but can never mint a finding, establish a
//! verdict, or cause an effect — the mirror of the generator wall.
//!
//! ## Why this crate carries no `smash-*` dependency (yet)
//!
//! The pure-data core is serde-native, and dedup keys off the candidate's canonical-key
//! *string* (`smash_generator::candidate::CanonicalKey` is core-only / not serde, so the
//! ledger stores its stable string rendering — the same mirror pattern
//! `smash_engine::matchlog::VerdictRecord` uses for a core `Verdict`). Projecting real
//! `Candidate`s and `RunBundle`s into records is **ingest**, which adds the
//! `smash-generator` / `smash-loop` / `smash-engine` dependencies behind the `ingest`
//! feature. Keeping the core dependency-free means it compiles and is tested in isolation.
//!
//! ## Modules
//!
//! - [`record`] — the [`CandidateRecord`](record::CandidateRecord) schema and the
//!   typed, serde-native fields it mirrors (incl. the ingest-populated
//!   [`MechanismId`](record::MechanismId) + evidence signature the clustering predicate
//!   groups on).
//! - [`lifecycle`] — the state machine and legal-transition enforcement.
//! - [`ledger`] — the append-only ledger: dedup/occurrence + JSONL read/write.
//! - [`coverage`] — coverage aggregation across packs (the "what did we search?"
//!   read-model); its roll-up is pure data, its projection from a live
//!   `RegionCoverage` is behind the `ingest` feature.
//! - [`triage`] — the pending-ratification queue: suggested clusters + severity ×
//!   novelty × fidelity ranking (pure data; severity via a [`triage::SeveritySource`]).
//! - [`cluster`] — the **registered deterministic** clustering predicate + retention
//!   (autonomous-loop §7, §5.2): the precise, versioned grouping the run report/capstone
//!   use, feeding `triage`'s advisory suggestion while the human still owns boundaries.
//! - [`commands`] — the human verbs (disposition, promote) and the [`commands::Store`]
//!   that loads/saves both ledgers.
//! - `ingest` — project real `Candidate` / `RunBundle` artifacts into records
//!   (behind the `ingest` feature; the only part that depends on the workspace).

pub mod cluster;
pub mod commands;
pub mod coverage;
pub mod ledger;
pub mod lifecycle;
pub mod record;
pub mod triage;

#[cfg(feature = "ingest")]
pub mod ingest;

pub use cluster::{
    cluster_findings, retention_plan, Cluster, ClusterKey, ClusterReport, RetentionPlan,
    CLUSTER_PREDICATE_VERSION,
};
pub use commands::{disposition, promote, CommandError, Decision, Store};
pub use coverage::{CoverageFact, CoverageKey, CoverageLedger, CoverageStatus, TargetCoverage};
pub use ledger::Ledger;
pub use triage::{
    next_action, suggested_cluster, triage, ClusterSummary, NextAction, Severity, SeverityMap,
    SeveritySource, TriageEntry, TriageReport,
};

#[cfg(feature = "ingest")]
pub use ingest::{
    admitted_outcome, default_fidelity, ingest_run, record_denied, record_from_run,
    record_rejected, verdict_class, verified_bundle_ref, IngestError, RunItem,
};
pub use lifecycle::{
    apply_transition, initial_state, is_legal_transition, promote_to_regression, seat_initial,
    RegressionProof, TransitionError,
};
pub use record::{
    AdmissionOutcome, BundleRef, CandidateKey, CandidateRecord, ClusterId, Disposition,
    EvidenceFidelity, LifecycleState, MechanismId, ProvenanceRecord, RejectReason, Transition,
    VerdictClass,
};
