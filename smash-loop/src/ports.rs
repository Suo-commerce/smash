//! The port traits that keep the loop decoupled from the engine and the target
//! (executor-referee, `v0.3 §1`/§4). Real impls live in `smash-engine` /
//! `smash-generator`; tests use fakes.
//!
//! Reconciliation note: denials now compose core's capability [`Denial`] (the gate
//! reasons: out-of-scope / authority / expiry / budget) with the engine-side
//! admission reasons this layer adds — region-assignability (M7), oracle binding
//! (N7), and parameter bounds (stage 2, [`ParamError`]). Dispatch/judge speak
//! [`ProbeOutcome`] (core `Verdict` projected, [`crate::verdict`]); the engine's real
//! oracle produces a `Verdict` and classifies `Inconclusive` into an
//! [`InconclusiveReason`] at that boundary.
//!
//! The walls are in the signatures: [`Generator`] gets no dispatcher, capability, or
//! raw output; [`Dispatcher`] is the only path to the wire and only the controller
//! holds one; there is no promotion port anywhere the loop can reach (acceptance 4,
//! structural half).

use crate::coverage::Completeness;
use crate::epoch::DispatchContext;
use crate::feedback::TypedFeedback;
use crate::param_check::ParamError;
use crate::plan::PlanEntry;
use crate::quiescence::ClearProof;
use crate::verdict::ProbeOutcome;
use crate::{CanonicalKey, RegionId};
use smash_core::capability::Denial as GateDenial;
use smash_engine::registry::TechniqueHandle;
use smash_generator::candidate::ParamValue;
use std::collections::BTreeMap;

/// Proposed candidate content, before admission. The generator's declarative output
/// (`boundary §3`), assigned a region by admission.
///
/// Carries the candidate's **validated declarative params** (admission-funnel
/// decision 2): admission bounds-checks these against the template's `ParamSpecSet`
/// (stage 2) before assigning a region, and dispatch binds to this exact payload. The
/// proposal is treated as immutable once admitted.
///
/// It also carries the **technique handle** (fighter + technique) it exercises.
/// Admission resolves that handle against the region/engine/bounds registries and
/// **recomputes** the canonical key from the handle + validated params
/// (admission-funnel §2.1). The generator supplies `key`, but admission never trusts
/// it — a supplied key could alias two different candidates or split one; only the
/// recomputed key binds dedup and poison.
#[derive(Clone, Debug)]
pub struct CandidateProposal {
    /// The generator's precomputed key. **Advisory only** — admission recomputes the
    /// canonical key from the handle + validated params and uses that instead (§2.1).
    pub key: CanonicalKey,
    /// The technique handle this candidate exercises — the (fighter, technique) pair
    /// admission resolves and recomputes the key from.
    pub handle: TechniqueHandle,
    /// The generator's intended region; admission re-checks assignability (M7).
    pub intended_region: RegionId,
    /// The declarative param map (slot → value) the template's `ParamSpecSet` bounds.
    pub params: BTreeMap<String, ParamValue>,
}

/// The strategy. Proposes; adjusts on typed feedback. No dispatch, no raw output.
pub trait Generator {
    fn propose(&mut self) -> Vec<CandidateProposal>;
    fn adjust(&mut self, feedback: &TypedFeedback);
}

/// An admission denial — a **plan-level** fact (N3), never a probe attempt. Composes
/// core's capability-gate [`GateDenial`] with the admission-layer reasons.
///
/// Note (N7): a missing oracle binding is **not** a denial — it is an *exploratory*
/// admission, capped at `Inconclusive` (see [`crate::regions::AdmittedRegion`]). Only
/// a gate denial, an unassignable region, or a parameter-bounds failure stops a
/// candidate here.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AdmissionDenial {
    /// A capability-gate denial from `smash_core` (scope/authority/expiry/budget).
    Gate(GateDenial),
    /// The candidate's intended region is not in the declared partition for its
    /// technique handle — unassignable (M7).
    NotRegionAssignable,
    /// A parameter failed the template's declared bounds (stage 2). Recorded as a
    /// `RejectedAtAdmission` coverage fact, never a silent clamp, never a pass.
    ParamOutOfBounds(ParamError),
}

/// Admission (`boundary §4`): parameter bounds (stage 2), scope/authority/effect, region
/// assignability (M7), reservation, oracle-binding. Returns an admitted entry or a typed
/// denial.
pub trait Admission {
    fn admit(&mut self, proposal: &CandidateProposal) -> Result<PlanEntry, AdmissionDenial>;
}

/// Fixture provisioning (`staging`). Reset to a clean epoch; teardown must cover
/// background/async work (`staging §3`) — the quiescence proof the barrier needs
/// comes from here.
pub trait FixtureProvisioner {
    fn reset(&mut self, ctx: &DispatchContext) -> Result<(), ResetError>;
    fn try_clear_proof(&mut self, offending: &CanonicalKey) -> Option<ClearProof>;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResetError(pub String);

/// The only path to the wire. Only the controller holds a `Dispatcher`; the
/// generator never sees one (the compile-time no-dispatch wall, `phase-2 §7`).
/// The dispatcher mints the real `Call`/`CallKey`, completes the `CorrelationKey`
/// via `ctx.correlation(..)`, fires through the capability gate + transport, and
/// returns the raw [`ProbeOutcome`] before judgement.
pub trait Dispatcher {
    fn execute(&mut self, entry: &PlanEntry, ctx: &DispatchContext) -> ProbeOutcome;
}

/// The single verdict authority (`differential::judge()`), parameterized per template
/// by its registered oracle. The loop routes to it and does not evaluate (P3 §0).
pub trait Oracle {
    fn judge(&self, entry: &PlanEntry, raw: ProbeOutcome) -> ProbeOutcome;
}

/// The operator kill switch (P3 §3.1; acceptance 1). Polled before each dispatch.
pub trait KillSwitch {
    fn should_halt(&self) -> bool;
}

/// A run summary the controller emits for the report (subset for item 1).
#[derive(Clone, Debug)]
pub struct RunReport {
    pub completeness: Completeness,
    pub any_confirmed_fail: bool,
}
