//! The dispatch plan: the **atomic** admit/defer unit (P3 §1 step 1, M1).
//!
//! A mutating probe is never dispatched without its positive write control. The
//! plan is therefore admitted **in full or deferred whole** — a partial fit never
//! dispatches a probe whose control did not fit. Controls are rostered **by scope**
//! (per-run read, per-probe write) so the ceiling arithmetic is complete.

use crate::epoch::Role;
use crate::{CanonicalKey, RegionId};

/// The scope at which a control is required (M1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ControlScope {
    /// Read-reachability, once per run.
    PerRun,
    /// Positive write control, once per probe, in its own namespace/epoch.
    PerProbe,
}

/// One entry in a dispatch plan. A probe entry carries its canonical key; a control
/// entry carries its scope. Each entry is independently reserved and gets its own
/// execution identity (and therefore its own epoch) at reset time.
#[derive(Clone, Debug)]
pub enum PlanEntry {
    Probe {
        key: CanonicalKey,
        region: RegionId,
        /// Whether this probe draws baseline (protected) or intensification budget.
        kind: ProbeKind,
        cost: crate::ceiling::Budget,
    },
    Control {
        scope: ControlScope,
        /// The probe this control backs (for `PerProbe`); `None` for `PerRun`.
        backs: Option<CanonicalKey>,
        role: Role,
        cost: crate::ceiling::Budget,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProbeKind {
    Baseline,
    Intensification,
}

/// A planned, not-yet-dispatched unit. Admitted in full or deferred whole.
#[derive(Clone, Debug, Default)]
pub struct DispatchPlan {
    pub entries: Vec<PlanEntry>,
}

impl DispatchPlan {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Build the atomic unit for a mutating probe: the probe plus its per-probe
    /// write control (`v0.3 §7`). The per-run read control is added separately, once.
    pub fn mutating_probe(
        key: CanonicalKey,
        region: RegionId,
        kind: ProbeKind,
        probe_cost: crate::ceiling::Budget,
        write_control_cost: crate::ceiling::Budget,
    ) -> Self {
        Self {
            entries: vec![
                PlanEntry::Control {
                    scope: ControlScope::PerProbe,
                    backs: Some(key.clone()),
                    role: Role::WriteControl,
                    cost: write_control_cost,
                },
                PlanEntry::Probe { key, region, kind, cost: probe_cost },
            ],
        }
    }

    /// Total cost of the whole plan — what must fit for an all-or-defer admission.
    pub fn total_cost(&self) -> crate::ceiling::Budget {
        self.entries
            .iter()
            .map(|e| match e {
                PlanEntry::Probe { cost, .. } => *cost,
                PlanEntry::Control { cost, .. } => *cost,
            })
            .sum()
    }

    /// The probe entries' regions, for quiescence/poison re-checks at step 3.
    pub fn probe_regions(&self) -> Vec<RegionId> {
        self.entries
            .iter()
            .filter_map(|e| match e {
                PlanEntry::Probe { region, .. } => Some(region.clone()),
                _ => None,
            })
            .collect()
    }

    /// Whether the plan contains at least one mutating probe (so the quiescence
    /// barrier must be clear before it is authorized — P3 §1 step 3).
    pub fn has_mutating_probe(&self) -> bool {
        self.entries.iter().any(|e| matches!(e, PlanEntry::Probe { .. }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutating_probe_always_carries_its_write_control() {
        let p = DispatchPlan::mutating_probe(
            CanonicalKey("c1".into()),
            RegionId("r0".into()),
            ProbeKind::Baseline,
            1,
            1,
        );
        assert_eq!(p.entries.len(), 2);
        let has_write_control = p.entries.iter().any(|e| matches!(
            e,
            PlanEntry::Control { scope: ControlScope::PerProbe, .. }
        ));
        assert!(has_write_control, "probe must be planned with its write control");
        assert_eq!(p.total_cost(), 2);
    }
}
