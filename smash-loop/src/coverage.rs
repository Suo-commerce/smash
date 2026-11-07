//! The two-axis coverage model: `search_status × cause_set`, `sample-resolved`,
//! deterministic reporting precedence, and the completeness field (P3 §0.2, §5.1;
//! acceptance 16).
//!
//! Reconciliation note: coverage now consumes [`ProbeOutcome`] (core `Verdict`
//! projected, [`crate::verdict`]) rather than a shim. The latency channel (N1) is
//! `Inconclusive(Timeout)`; a broken control or other oracle-inconclusive is
//! `unresolved_verdict` (N2). Denials are never passed here — they are plan-level
//! `planner_denials` (N3).

use crate::verdict::{InconclusiveReason, ProbeOutcome};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SearchStatus {
    Unvisited,
    Partial,
    Sampled,
}

/// A resolvability cause. `PlannerDenied` is deliberately absent — denials are a
/// parallel annotation (N3), carried as `planner_denials`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Cause {
    Poisoned,
    OpError,
    OpTimeout,
    UnresolvedVerdict,
    InadequateSample,
    Unvisited,
}

impl Cause {
    fn precedence_rank(self) -> u8 {
        match self {
            Cause::Poisoned => 0,
            Cause::OpError => 1,
            Cause::OpTimeout => 2,
            Cause::UnresolvedVerdict => 3,
            Cause::InadequateSample => 4,
            Cause::Unvisited => 5,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RegionCoverage {
    pub status: SearchStatus,
    pub causes: Vec<Cause>,
    pub planner_denials: u32,
    pub throttled: bool,
}

impl RegionCoverage {
    /// Compute a region's state from its **dispatched-probe** outcomes (N3), the
    /// adequacy target, poison, and plan-level annotations.
    pub fn compute(
        outcomes: &[ProbeOutcome],
        adequacy_target: u64,
        poisoned: bool,
        planner_denials: u32,
        throttled: bool,
    ) -> Self {
        let attempts = outcomes.len() as u64;
        let status = if attempts == 0 {
            SearchStatus::Unvisited
        } else if attempts < adequacy_target {
            SearchStatus::Partial
        } else {
            SearchStatus::Sampled
        };

        let mut causes: Vec<Cause> = Vec::new();
        if poisoned {
            causes.push(Cause::Poisoned);
        }
        if outcomes.contains(&ProbeOutcome::Error) {
            causes.push(Cause::OpError);
        }
        if outcomes.contains(&ProbeOutcome::Inconclusive(InconclusiveReason::Timeout)) {
            causes.push(Cause::OpTimeout);
        }
        // Any non-timeout inconclusive (broken control, ambiguous routing, …) → N2.
        if outcomes.iter().any(|o| {
            matches!(o, ProbeOutcome::Inconclusive(r) if *r != InconclusiveReason::Timeout)
        }) {
            causes.push(Cause::UnresolvedVerdict);
        }
        match status {
            SearchStatus::Unvisited => causes.push(Cause::Unvisited),
            SearchStatus::Partial => causes.push(Cause::InadequateSample),
            SearchStatus::Sampled => {}
        }

        causes.sort_by_key(|c| c.precedence_rank());
        causes.dedup();

        Self { status, causes, planner_denials, throttled }
    }

    /// `sample-resolved` iff `Sampled` and every attempt resolved to Pass/Fail — the
    /// only state that counts as coverage (N1). Fails in it are findings.
    pub fn is_sample_resolved(&self) -> bool {
        self.status == SearchStatus::Sampled && self.causes.is_empty()
    }

    pub fn summary_cause(&self) -> Option<Cause> {
        self.causes.first().copied()
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Completeness {
    Complete,
    Incomplete {
        gap_causes: std::collections::BTreeMap<CauseKey, u32>,
        planner_denials_total: u32,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct CauseKey(pub u8);

impl From<Cause> for CauseKey {
    fn from(c: Cause) -> Self {
        CauseKey(c.precedence_rank())
    }
}

pub fn completeness(regions: &[RegionCoverage]) -> Completeness {
    if regions.iter().all(|r| r.is_sample_resolved()) {
        return Completeness::Complete;
    }
    let mut gap_causes = std::collections::BTreeMap::new();
    let mut denials = 0u32;
    for r in regions {
        denials = denials.saturating_add(r.planner_denials);
        if !r.is_sample_resolved() {
            if let Some(c) = r.summary_cause() {
                *gap_causes.entry(CauseKey::from(c)).or_insert(0) += 1;
            }
        }
    }
    Completeness::Incomplete { gap_causes, planner_denials_total: denials }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{InconclusiveReason, ProbeOutcome::*};

    #[test]
    fn inadequate_sample_is_a_gap_not_coverage() {
        let cov = RegionCoverage::compute(&[Pass, Pass, Pass], 10, false, 0, false);
        assert_eq!(cov.status, SearchStatus::Partial);
        assert!(!cov.is_sample_resolved());
        assert_eq!(cov.summary_cause(), Some(Cause::InadequateSample));
    }

    #[test]
    fn oracle_inconclusive_is_representable() {
        // N2: a broken control (non-timeout inconclusive) → unresolved_verdict.
        let cov = RegionCoverage::compute(
            &[Pass, Fail, Inconclusive(InconclusiveReason::BrokenControl)],
            3, false, 0, false,
        );
        assert_eq!(cov.status, SearchStatus::Sampled);
        assert!(!cov.is_sample_resolved());
        assert_eq!(cov.summary_cause(), Some(Cause::UnresolvedVerdict));
    }

    #[test]
    fn latency_timeout_is_op_timeout_not_unresolved() {
        // N1: a target-induced timeout is its own cause, distinct from a broken control.
        let cov = RegionCoverage::compute(
            &[Pass, Inconclusive(InconclusiveReason::Timeout)],
            2, false, 0, true,
        );
        assert!(cov.causes.contains(&Cause::OpTimeout));
        assert!(!cov.causes.contains(&Cause::UnresolvedVerdict));
        assert!(cov.throttled);
        assert!(!cov.is_sample_resolved());
    }

    #[test]
    fn sample_resolved_counts_even_with_fails() {
        let cov = RegionCoverage::compute(&[Pass, Fail, Pass], 3, false, 0, false);
        assert!(cov.is_sample_resolved());
    }

    #[test]
    fn denial_plus_unresolved_effect_coexist_with_precedence() {
        let cov = RegionCoverage::compute(
            &[Pass, Inconclusive(InconclusiveReason::Timeout)], 2, true, 4, false);
        assert_eq!(cov.planner_denials, 4);
        assert_eq!(cov.summary_cause(), Some(Cause::Poisoned));
        assert!(cov.causes.contains(&Cause::OpTimeout));
    }

    #[test]
    fn denials_do_not_deny_resolvability_of_dispatched_probes() {
        let cov = RegionCoverage::compute(&[Pass, Pass], 2, false, 7, false);
        assert!(cov.is_sample_resolved());
        assert_eq!(cov.planner_denials, 7);
    }

    #[test]
    fn completeness_is_complete_only_when_all_resolved() {
        let r0 = RegionCoverage::compute(&[Pass, Fail], 2, false, 0, false);
        let r1 = RegionCoverage::compute(
            &[Pass, Inconclusive(InconclusiveReason::Timeout)], 2, false, 0, false);
        assert_eq!(completeness(&[r0.clone(), r0.clone()]), Completeness::Complete);
        match completeness(&[r0, r1]) {
            Completeness::Incomplete { gap_causes, .. } => {
                assert_eq!(gap_causes.get(&CauseKey::from(Cause::OpTimeout)), Some(&1));
            }
            Completeness::Complete => panic!("one region is a gap"),
        }
    }
}
