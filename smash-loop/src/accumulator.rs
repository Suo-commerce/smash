//! The run-scoped outcome **accumulator** — the orchestrator's data backbone
//! (build-order item 3, sub-unit toward the loop).
//!
//! The adaptive loop produces, each iteration, a handful of per-region dispatched
//! outcomes. Four different consumers need that history shaped four different ways:
//! [`crate::coverage`] (the two-axis `RegionCoverage`), [`crate::driver`] (the
//! run-wide `any_confirmed_fail` + `all_regions_sample_resolved` stop signals),
//! [`crate::steering`] (per-region [`RegionObservation`]s), and [`crate::feedback`]
//! (the typed, tokenized `TypedFeedback` handed to the generator). This accumulator is
//! the single run-scoped place that history lives, so those four views can never drift
//! apart.
//!
//! It is **envelope-seeded**: constructed from the declared envelope's per-region
//! `adequacy_target`, so a region that is never dispatched still appears as `Unvisited`
//! (a named gap), not silently absent — the completeness field and the abort
//! denominator both depend on that (P3 §0.2, §3.3). It records **dispatched-probe**
//! outcomes only (N3); a plan-level admission denial is a separate `planner_denials`
//! count, never an attempt. Determinism: everything iterates the envelope in
//! `RegionId` order.

use crate::coverage::RegionCoverage;
use crate::feedback::{
    FeedbackAssembler, RegionFeedback, RegionFeedbackData, TypedFeedback, VerdictCounts,
};
use crate::steering::RegionObservation;
use crate::verdict::{InconclusiveReason, ProbeOutcome};
use crate::{CanonicalKey, RegionId};
use std::collections::BTreeMap;

/// One region's accumulated run history. Dispatched outcomes (N3), the finding keys of
/// its `Fail`s, the plan-level denial count, and the poison/throttle annotations.
#[derive(Clone, Debug, Default)]
struct RegionAccum {
    outcomes: Vec<ProbeOutcome>,
    finding_keys: Vec<CanonicalKey>,
    planner_denials: u32,
    poisoned: bool,
    throttled: bool,
}

impl RegionAccum {
    fn counts(&self) -> VerdictCounts {
        let mut c = VerdictCounts::default();
        for o in &self.outcomes {
            match o {
                ProbeOutcome::Pass => c.pass += 1,
                ProbeOutcome::Fail => c.fail += 1,
                ProbeOutcome::Error => c.error += 1,
                ProbeOutcome::Inconclusive(InconclusiveReason::Timeout) => c.timeout += 1,
                ProbeOutcome::Inconclusive(_) => c.inconclusive += 1,
            }
        }
        c.denied = self.planner_denials;
        c
    }
}

/// The run's outcome accumulator, seeded with the declared envelope (region →
/// `adequacy_target`). Records dispatched outcomes and plan-level facts, and projects
/// the four views the loop needs.
#[derive(Clone, Debug)]
pub struct RunAccumulator {
    adequacy: BTreeMap<RegionId, u64>,
    regions: BTreeMap<RegionId, RegionAccum>,
}

impl RunAccumulator {
    /// Seed from the envelope's per-region adequacy targets. Every envelope region is
    /// present from the start (as `Unvisited` until dispatched).
    pub fn new(adequacy: BTreeMap<RegionId, u64>) -> Self {
        let regions = adequacy.keys().map(|r| (r.clone(), RegionAccum::default())).collect();
        Self { adequacy, regions }
    }

    fn accum_mut(&mut self, region: &RegionId) -> Option<&mut RegionAccum> {
        // Only envelope regions are tracked; a record for a non-envelope region is a
        // caller bug and is ignored rather than silently inventing a region.
        if self.adequacy.contains_key(region) {
            Some(self.regions.entry(region.clone()).or_default())
        } else {
            None
        }
    }

    /// Record one **dispatched** probe's resolved outcome (N3). The `key` is the
    /// candidate's canonical key; a `Fail` adds it to the region's finding keys.
    pub fn record_outcome(&mut self, region: &RegionId, key: &CanonicalKey, outcome: ProbeOutcome) {
        if let Some(acc) = self.accum_mut(region) {
            if outcome == ProbeOutcome::Fail {
                acc.finding_keys.push(key.clone());
            }
            acc.outcomes.push(outcome);
        }
    }

    /// Record a plan-level admission denial for a region (N3) — not an attempt.
    pub fn record_denial(&mut self, region: &RegionId) {
        if let Some(acc) = self.accum_mut(region) {
            acc.planner_denials = acc.planner_denials.saturating_add(1);
        }
    }

    /// Mark a region poisoned (an unresolved mutating effect, from `quiescence`).
    pub fn set_poisoned(&mut self, region: &RegionId) {
        if let Some(acc) = self.accum_mut(region) {
            acc.poisoned = true;
        }
    }

    /// Mark a region throttled (from `steering`). Sticky — never unset here (n6).
    pub fn set_throttled(&mut self, region: &RegionId) {
        if let Some(acc) = self.accum_mut(region) {
            acc.throttled = true;
        }
    }

    fn adequacy_of(&self, region: &RegionId) -> u64 {
        self.adequacy.get(region).copied().unwrap_or(0)
    }

    fn coverage_of(&self, region: &RegionId) -> RegionCoverage {
        let empty = RegionAccum::default();
        let acc = self.regions.get(region).unwrap_or(&empty);
        RegionCoverage::compute(
            &acc.outcomes,
            self.adequacy_of(region),
            acc.poisoned,
            acc.planner_denials,
            acc.throttled,
        )
    }

    /// The two-axis coverage for every envelope region, in `RegionId` order — the
    /// input to [`crate::driver::conclude`]'s completeness field.
    pub fn all_coverage(&self) -> Vec<RegionCoverage> {
        self.adequacy.keys().map(|r| self.coverage_of(r)).collect()
    }

    /// Per-region observations for [`crate::steering::decide`], in `RegionId` order.
    pub fn observations(&self) -> Vec<RegionObservation> {
        self.adequacy
            .keys()
            .map(|region| {
                let empty = RegionAccum::default();
                let acc = self.regions.get(region).unwrap_or(&empty);
                RegionObservation {
                    region: region.clone(),
                    attempts: acc.outcomes.len() as u64,
                    coverage: self.coverage_of(region),
                    fail_seen: acc.outcomes.contains(&ProbeOutcome::Fail),
                    already_throttled: acc.throttled,
                }
            })
            .collect()
    }

    /// Run-wide: at least one dispatched probe resolved to `Fail` (drives the exit
    /// code, P3 §4.2).
    pub fn any_confirmed_fail(&self) -> bool {
        self.regions
            .values()
            .any(|a| a.outcomes.contains(&ProbeOutcome::Fail))
    }

    /// Run-wide: every envelope region is sample-resolved — the earned-saturation stop
    /// signal (P3 §4.3 precedence 7).
    pub fn all_regions_sample_resolved(&self) -> bool {
        self.adequacy.keys().all(|r| self.coverage_of(r).is_sample_resolved())
    }

    /// Build the typed, tokenized feedback batch for `generator.adjust`. Every field is
    /// an enum, a count, a bool, or a service-minted key — never target text (P3 §2.1).
    /// The [`FeedbackAssembler`] is the trusted surface that mints the token.
    pub fn typed_feedback(&self, assembler: &FeedbackAssembler) -> TypedFeedback {
        let regions = self
            .adequacy
            .keys()
            .map(|region| {
                let empty = RegionAccum::default();
                let acc = self.regions.get(region).unwrap_or(&empty);
                let cov = self.coverage_of(region);
                RegionFeedback::new(
                    assembler.token(),
                    RegionFeedbackData {
                        region_id: region.clone(),
                        search_status: cov.status,
                        cause_set: cov.causes.clone(),
                        planner_denials: acc.planner_denials,
                        throttled: acc.throttled,
                        counts: acc.counts(),
                        finding_keys: acc.finding_keys.clone(),
                    },
                )
            })
            .collect();
        TypedFeedback::new(regions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::SearchStatus;
    use crate::verdict::{InconclusiveReason, ProbeOutcome::*};

    fn region(n: &str) -> RegionId {
        RegionId(n.into())
    }
    fn key(n: &str) -> CanonicalKey {
        CanonicalKey(n.into())
    }

    fn acc() -> RunAccumulator {
        RunAccumulator::new(BTreeMap::from([(region("r0"), 2), (region("r1"), 2)]))
    }

    #[test]
    fn envelope_regions_start_unvisited() {
        let a = acc();
        let cov = a.all_coverage();
        assert_eq!(cov.len(), 2);
        assert!(cov.iter().all(|c| c.status == SearchStatus::Unvisited));
        assert!(!a.any_confirmed_fail());
        assert!(!a.all_regions_sample_resolved());
    }

    #[test]
    fn records_outcomes_into_counts_and_coverage() {
        let mut a = acc();
        a.record_outcome(&region("r0"), &key("c1"), Pass);
        a.record_outcome(&region("r0"), &key("c2"), Fail);
        a.record_outcome(&region("r1"), &key("c3"), Pass);
        a.record_outcome(&region("r1"), &key("c4"), Pass);
        assert!(a.any_confirmed_fail());
        // r0: [Pass, Fail] at adequacy 2 → sample-resolved; r1: [Pass, Pass] → resolved.
        assert!(a.all_regions_sample_resolved());
        let obs = a.observations();
        let r0 = obs.iter().find(|o| o.region == region("r0")).unwrap();
        assert_eq!(r0.attempts, 2);
        assert!(r0.fail_seen);
    }

    #[test]
    fn a_region_short_of_adequacy_is_not_resolved() {
        let mut a = acc();
        a.record_outcome(&region("r0"), &key("c1"), Pass);
        // r0 has 1 attempt (< adequacy 2), r1 has 0 → not all resolved.
        assert!(!a.all_regions_sample_resolved());
    }

    #[test]
    fn denials_are_counted_without_being_attempts() {
        let mut a = acc();
        a.record_denial(&region("r0"));
        a.record_denial(&region("r0"));
        let obs = a.observations();
        let r0 = obs.iter().find(|o| o.region == region("r0")).unwrap();
        assert_eq!(r0.attempts, 0, "a denial is not a dispatched attempt");
        assert_eq!(r0.coverage.planner_denials, 2);
    }

    #[test]
    fn poison_and_throttle_annotations_flow_through() {
        let mut a = acc();
        a.record_outcome(&region("r0"), &key("c1"), Pass);
        a.set_poisoned(&region("r0"));
        a.set_throttled(&region("r0"));
        let obs = a.observations();
        let r0 = obs.iter().find(|o| o.region == region("r0")).unwrap();
        assert!(r0.already_throttled);
        assert!(r0.coverage.throttled);
        // Poison is a cause → not sample-resolved even though the one outcome passed.
        assert!(!r0.coverage.is_sample_resolved());
    }

    #[test]
    fn typed_feedback_carries_counts_and_finding_keys() {
        let mut a = acc();
        a.record_outcome(&region("r0"), &key("find-1"), Fail);
        a.record_outcome(&region("r0"), &key("c2"), Inconclusive(InconclusiveReason::Timeout));
        a.record_denial(&region("r0"));
        let fb = a.typed_feedback(&FeedbackAssembler);
        let rf = fb.regions().iter().find(|r| *r.region_id() == region("r0")).unwrap();
        assert_eq!(rf.counts().fail, 1);
        assert_eq!(rf.counts().timeout, 1);
        assert_eq!(rf.counts().denied, 1);
        assert_eq!(rf.finding_keys(), &[key("find-1")]);
    }

    #[test]
    fn records_for_non_envelope_regions_are_ignored() {
        let mut a = acc();
        a.record_outcome(&region("ghost"), &key("x"), Fail);
        assert!(!a.any_confirmed_fail(), "a non-envelope region is not tracked");
        assert_eq!(a.all_coverage().len(), 2);
    }
}
