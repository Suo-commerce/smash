//! The run-level **quiescence barrier**, canonical-key + region poison, and
//! queued-entry invalidation (P3 §3.4; internal-review finding 4; acceptance 7).
//!
//! The principle a fresh fixture does **not** establish: that an asynchronous or
//! downstream operation has stopped. So an unresolved mutating attempt does three
//! things — poisons its key and region, invalidates queued entries in that region,
//! and raises a run-level barrier that blocks **all** further mutating dispatch
//! until the controller records **quiescence proof** or **isolation proof**, or the
//! bounded `quiescence_wait` elapses and the run **aborts**.

use crate::{CanonicalKey, RegionId};
use smash_core::lifecycle::AttemptState;
use std::collections::BTreeSet;

/// Proof that lets the barrier clear (P3 §3.4). Both are recorded in the bundle.
#[derive(Clone, Debug)]
pub enum ClearProof {
    /// The fixture's completion barrier shows the operation terminated
    /// (`v0.3 §7` step 5 / `v0.3 §9`).
    Quiescence { evidence_digest: String },
    /// The next fixture is provably unreachable by the prior operation — distinct
    /// downstream, no shared mutable dependency (`staging §3`).
    Isolation { evidence_digest: String },
}

/// Why the run aborted, when it does.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BarrierAbort {
    /// `quiescence_wait` elapsed with neither proof recorded.
    QuiescenceTimeout,
}

/// Barrier state. `Clear` permits mutating dispatch; `Blocked` forbids it until a
/// proof arrives or the wait elapses.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BarrierState {
    Clear,
    Blocked { since_tick: u64, offending_key: CanonicalKey },
    Aborted(BarrierAbort),
}

/// Tracks poison (keys + regions) and the barrier. `tick` is a logical clock the
/// controller advances once per iteration; `quiescence_wait` is measured in ticks.
#[derive(Debug)]
pub struct Quiescence {
    poisoned_keys: BTreeSet<CanonicalKey>,
    poisoned_regions: BTreeSet<RegionId>,
    state: BarrierState,
    quiescence_wait: u64,
}

impl Quiescence {
    pub fn new(quiescence_wait: u64) -> Self {
        Self {
            poisoned_keys: BTreeSet::new(),
            poisoned_regions: BTreeSet::new(),
            state: BarrierState::Clear,
            quiescence_wait,
        }
    }

    pub fn state(&self) -> &BarrierState {
        &self.state
    }

    pub fn is_region_poisoned(&self, region: &RegionId) -> bool {
        self.poisoned_regions.contains(region)
    }

    pub fn is_key_poisoned(&self, key: &CanonicalKey) -> bool {
        self.poisoned_keys.contains(key)
    }

    /// Record a dispatched attempt's resolution against the core lifecycle honesty
    /// contract (`smash_core::lifecycle::AttemptState`): only `Unresolved` raises the
    /// barrier and poisons. `Resolved` is a no-op; `Intended`/`Dispatched` are not
    /// terminal and are ignored here. This is the single entry point the controller
    /// uses, so the barrier can never be triggered by anything but a genuinely
    /// unresolved effect.
    pub fn record_attempt(
        &mut self,
        state: AttemptState,
        key: CanonicalKey,
        region: RegionId,
        tick: u64,
    ) {
        if state == AttemptState::Unresolved {
            self.record_unresolved(key, region, tick);
        }
    }

    /// Record an unresolved mutating attempt: poison its key and region, and raise
    /// the barrier if not already raised/aborted (P3 §3.4).
    pub fn record_unresolved(&mut self, key: CanonicalKey, region: RegionId, tick: u64) {
        self.poisoned_keys.insert(key.clone());
        self.poisoned_regions.insert(region);
        if let BarrierState::Clear = self.state {
            self.state = BarrierState::Blocked { since_tick: tick, offending_key: key };
        }
    }

    /// May a mutating dispatch proceed right now? Only when the barrier is `Clear`.
    pub fn may_dispatch_mutating(&self) -> bool {
        matches!(self.state, BarrierState::Clear)
    }

    /// Record a clearing proof. Clears the barrier (keys/regions stay poisoned for
    /// the rest of the run — poison is run-scoped and never re-proposed).
    pub fn record_clear_proof(&mut self, _proof: ClearProof) {
        if matches!(self.state, BarrierState::Blocked { .. }) {
            self.state = BarrierState::Clear;
        }
    }

    /// Advance the clock. If the barrier has been blocked longer than
    /// `quiescence_wait`, the run aborts (P3 §3.4; acceptance 7).
    pub fn advance_tick(&mut self, now: u64) {
        if let BarrierState::Blocked { since_tick, .. } = &self.state {
            if now.saturating_sub(*since_tick) >= self.quiescence_wait {
                self.state = BarrierState::Aborted(BarrierAbort::QuiescenceTimeout);
            }
        }
    }

    pub fn is_aborted(&self) -> bool {
        matches!(self.state, BarrierState::Aborted(_))
    }

    /// Filter a planned batch, dropping every entry tied to a poisoned region or key
    /// — the queued-entry invalidation of P3 §1 step 3 (acceptance 7). A probe is
    /// dropped when its region or key is poisoned; a control is dropped when the
    /// probe **it backs** is being dropped (so a control is never left orphaned when
    /// its probe's region is poisoned, even though the control itself only names the
    /// probe's key). Returns the surviving entries and the count invalidated.
    pub fn invalidate_queued<'a, I>(&self, entries: I) -> (Vec<&'a crate::plan::PlanEntry>, usize)
    where
        I: IntoIterator<Item = &'a crate::plan::PlanEntry>,
    {
        use crate::plan::PlanEntry;
        let entries: Vec<&'a PlanEntry> = entries.into_iter().collect();

        // Pass 1: the doomed probe keys — probes whose region or key is poisoned.
        let mut doomed: BTreeSet<CanonicalKey> = BTreeSet::new();
        for e in &entries {
            if let PlanEntry::Probe { key, region, .. } = e {
                if self.is_region_poisoned(region) || self.is_key_poisoned(key) {
                    doomed.insert(key.clone());
                }
            }
        }

        // Pass 2: drop doomed probes and any control backing a doomed (or poisoned) key.
        let mut kept = Vec::new();
        let mut dropped = 0usize;
        for e in entries {
            let drop = match e {
                PlanEntry::Probe { key, .. } => doomed.contains(key),
                PlanEntry::Control { backs: Some(key), .. } => {
                    doomed.contains(key) || self.is_key_poisoned(key)
                }
                PlanEntry::Control { backs: None, .. } => false,
            };
            if drop {
                dropped += 1;
            } else {
                kept.push(e);
            }
        }
        (kept, dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{DispatchPlan, ProbeKind};

    #[test]
    fn unresolved_attempt_blocks_further_mutating_dispatch() {
        // Acceptance 7: a hang poisons key+region and raises the barrier.
        let mut q = Quiescence::new(3);
        assert!(q.may_dispatch_mutating());
        q.record_unresolved(CanonicalKey("c1".into()), RegionId("r0".into()), 0);
        assert!(!q.may_dispatch_mutating(), "barrier must block after unresolved effect");
        assert!(q.is_region_poisoned(&RegionId("r0".into())));
        assert!(q.is_key_poisoned(&CanonicalKey("c1".into())));
    }

    #[test]
    fn only_unresolved_attempt_state_raises_the_barrier() {
        // The lifecycle linkage: a Resolved attempt is a no-op; only Unresolved
        // (the core honesty-contract terminal for unknown effects) poisons.
        let mut q = Quiescence::new(3);
        q.record_attempt(AttemptState::Resolved, CanonicalKey("ok".into()), RegionId("r0".into()), 0);
        assert!(q.may_dispatch_mutating(), "a resolved attempt must not raise the barrier");
        q.record_attempt(AttemptState::Unresolved, CanonicalKey("c1".into()), RegionId("r0".into()), 0);
        assert!(!q.may_dispatch_mutating());
    }

    #[test]
    fn barrier_clears_only_on_proof() {
        let mut q = Quiescence::new(3);
        q.record_unresolved(CanonicalKey("c1".into()), RegionId("r0".into()), 0);
        q.record_clear_proof(ClearProof::Isolation { evidence_digest: "iso".into() });
        assert!(q.may_dispatch_mutating(), "isolation proof clears the barrier");
        // Poison persists for the run even after the barrier clears.
        assert!(q.is_region_poisoned(&RegionId("r0".into())));
    }

    #[test]
    fn barrier_aborts_after_quiescence_wait() {
        // Acceptance 7: absent proof within quiescence_wait, the run aborts.
        let mut q = Quiescence::new(3);
        q.record_unresolved(CanonicalKey("c1".into()), RegionId("r0".into()), 0);
        q.advance_tick(1);
        assert!(!q.is_aborted());
        q.advance_tick(3); // 3 - 0 >= 3
        assert!(q.is_aborted());
        assert_eq!(q.state(), &BarrierState::Aborted(BarrierAbort::QuiescenceTimeout));
    }

    #[test]
    fn queued_entries_in_poisoned_region_are_invalidated() {
        // Acceptance 7: a plan targeting a poisoned region is dropped at step 3.
        let mut q = Quiescence::new(3);
        q.record_unresolved(CanonicalKey("c0".into()), RegionId("r0".into()), 0);

        let p_bad = DispatchPlan::mutating_probe(
            CanonicalKey("c1".into()), RegionId("r0".into()), ProbeKind::Baseline, 1, 1);
        let p_ok = DispatchPlan::mutating_probe(
            CanonicalKey("c2".into()), RegionId("r1".into()), ProbeKind::Baseline, 1, 1);
        let all: Vec<_> = p_bad.entries.iter().chain(p_ok.entries.iter()).collect();
        let (kept, dropped) = q.invalidate_queued(all);
        // r0's probe + its control dropped (2); r1's probe + control kept (2).
        assert_eq!(dropped, 2);
        assert_eq!(kept.len(), 2);
    }
}
