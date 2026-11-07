//! Verdict vocabulary for the loop, on top of `smash_core::verdict::Verdict`.
//!
//! Reconciliation note (decision: typed `InconclusiveReason`): core's five-state
//! [`Verdict`] has **no `Timeout` variant** — a latency timeout is
//! `Verdict::Inconclusive { reason }`. N1's latency defense needs the loop to tell a
//! *target-induced timeout* (throttleable) apart from a *broken positive control*
//! (not throttleable), and both are `Inconclusive` in core. So the engine classifies
//! each `Inconclusive` into a typed [`InconclusiveReason`] rather than leaving the
//! loop to parse `reason` strings (which would also breach the manifest wall, since
//! `reason` is engine-authored but free-form).
//!
//! The loop works in [`ProbeOutcome`] — core `Verdict` projected to what a
//! *dispatched* probe can resolve to. `Denied` is **not** here: a denial is a
//! pre-dispatch, plan-level fact (N3), handled as `planner_denials`, never an attempt.

pub use smash_core::verdict::{EvidenceRef, TechniqueVerdict, Verdict, VerdictSummary};

/// The typed reason a dispatched probe's oracle returned `Inconclusive`
/// (decision 2). Maps core's documented `Inconclusive` causes — "broken control,
/// ambiguous routing, incomplete receipt/state data, unexpected rejection, or
/// unresolved completion" — onto a closed set the loop can branch on. `Timeout`
/// (unresolved completion observed as a timeout) is the only one the loop treats as
/// a throttleable, target-induced operational signal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InconclusiveReason {
    /// Unresolved completion observed as a timeout past the observation window —
    /// target-induced, throttleable (the N1 latency channel).
    Timeout,
    /// The positive control did not succeed, so the probe cannot be judged. Not
    /// target-induced; never a throttle trigger.
    BrokenControl,
    /// Routing was ambiguous.
    AmbiguousRouting,
    /// A receipt could not be correlated to this execution (core §8 collision).
    UncorrelatedReceipt,
    /// The target rejected the call in a way the oracle did not expect.
    UnexpectedRejection,
    /// Only partial evidence was collected.
    PartialObservation,
}

impl InconclusiveReason {
    /// Whether this reason is a target-induced operational signal the loop may
    /// throttle on (N3: only target-influenceable counters bound steering). Only
    /// `Timeout` qualifies; the rest are harness/oracle conditions.
    pub fn is_target_induced_operational(self) -> bool {
        matches!(self, InconclusiveReason::Timeout)
    }
}

/// What a single **dispatched** probe resolved to — core `Verdict` projected for the
/// loop. Pass/Fail are resolving; the rest are gaps with a cause.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProbeOutcome {
    /// `DEFENDED` for this candidate+fixture+invariant (core `Verdict::Pass`).
    Pass,
    /// `KILL` — confirmed violation (core `Verdict::Fail`).
    Fail,
    /// Infrastructure failure (core `Verdict::Error`) — target-induced op error.
    Error,
    /// The oracle could not judge (core `Verdict::Inconclusive`), with its typed reason.
    Inconclusive(InconclusiveReason),
}

impl ProbeOutcome {
    /// A confirmed security failure (drives the exit code, P3 §4.2).
    pub fn is_fail(self) -> bool {
        matches!(self, ProbeOutcome::Fail)
    }

    /// Resolved to a definite judgement (Pass or Fail). Only resolved probes can
    /// make a region `sample-resolved` (P3 §0.2).
    pub fn is_resolved(self) -> bool {
        matches!(self, ProbeOutcome::Pass | ProbeOutcome::Fail)
    }

    /// Project a core `Verdict` to a loop outcome. For `Inconclusive`, the engine
    /// supplies the typed `reason` (decision 2); `Denied` is rejected here because a
    /// denial is not a dispatched-probe outcome (N3) — callers handle it upstream.
    pub fn from_verdict(v: &Verdict, reason: Option<InconclusiveReason>) -> Option<Self> {
        match v {
            Verdict::Pass { .. } => Some(ProbeOutcome::Pass),
            Verdict::Fail { .. } => Some(ProbeOutcome::Fail),
            Verdict::Error { .. } => Some(ProbeOutcome::Error),
            Verdict::Inconclusive { .. } => reason.map(ProbeOutcome::Inconclusive),
            Verdict::Denied { .. } => None, // plan-level, not an attempt (N3)
            _ => None, // core Verdict is #[non_exhaustive]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smash_core::verdict::Verdict;

    #[test]
    fn timeout_is_the_only_throttleable_inconclusive() {
        assert!(InconclusiveReason::Timeout.is_target_induced_operational());
        assert!(!InconclusiveReason::BrokenControl.is_target_induced_operational());
        assert!(!InconclusiveReason::AmbiguousRouting.is_target_induced_operational());
    }

    #[test]
    fn verdict_projects_to_outcome() {
        assert_eq!(
            ProbeOutcome::from_verdict(&Verdict::Pass { evidence: vec![] }, None),
            Some(ProbeOutcome::Pass)
        );
        let inc = Verdict::Inconclusive { reason: "slow".into(), evidence: vec![] };
        assert_eq!(
            ProbeOutcome::from_verdict(&inc, Some(InconclusiveReason::Timeout)),
            Some(ProbeOutcome::Inconclusive(InconclusiveReason::Timeout))
        );
        // A dispatch-gate denial is not a dispatched-probe outcome.
        let denied = Verdict::Denied {
            denial: smash_core::capability::Denial::BudgetExceeded,
        };
        assert_eq!(ProbeOutcome::from_verdict(&denied, None), None);
    }
}
