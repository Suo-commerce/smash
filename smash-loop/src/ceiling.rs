//! Run-level **dispatch** ceiling, per-entry reservation, baseline **withholding**,
//! and the **feasibility preflight**.
//!
//! Three round-3 points live here:
//! - **M1:** the ceiling is defined over *dispatches* (candidates **and** controls),
//!   not candidates — controls consume budget and must be counted.
//! - **N4:** the baseline fairness guarantee is a planner **withholding**, not ledger
//!   bookkeeping: `admissible_plan_budget = remaining − Σ unserved_baseline − control
//!   reserve`, so a region cannot be starved by another region's intensification.
//! - **M2:** a feasibility **preflight** rejects an envelope that cannot fund its
//!   baseline + controls *before* any dispatch, so a run is never born unsatisfiable
//!   and then halts silently `incomplete`.

/// Budget unit. Abstract "cost" of one dispatch; the engine maps it to real request
/// budget. Kept as a plain integer so accounting is exact and testable.
pub type Budget = u64;

/// Parameters needed to reason about feasibility and withholding (subset of the
/// P3 §13 item 1 parameter set relevant to item 1).
#[derive(Clone, Debug)]
pub struct CeilingConfig {
    /// Total run-level dispatch budget (candidates + controls).
    pub ceiling: Budget,
    /// Cost of one probe dispatch.
    pub probe_cost: Budget,
    /// Cost of one write-control dispatch (per probe, `v0.3 §7`).
    pub write_control_cost: Budget,
    /// Cost of the per-run read-reachability control (`v0.3 §7`, amortized once).
    pub read_control_cost: Budget,
    /// `baseline_attempts` — probes each envelope region is guaranteed before the
    /// intensification ledger may be drawn (N4).
    pub baseline_attempts: u64,
}

/// Result of the start-of-run feasibility preflight (M2; acceptance 18).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Feasibility {
    Ok,
    /// The envelope cannot fund its baseline + controls within the ceiling. Carries
    /// the shortfall so the operator can distinguish this from target resistance.
    Infeasible { required: Budget, ceiling: Budget },
}

/// The run's budget accountant. Tracks reservations against the ceiling and the
/// withholding owed to regions that have not yet received their baseline.
#[derive(Debug)]
pub struct DispatchCeiling {
    cfg: CeilingConfig,
    reserved: Budget,
    /// Per-region count of baseline probes still owed (N4). While any region owes
    /// baseline, that budget is withheld from the admissible plan size.
    unserved_baseline: std::collections::BTreeMap<crate::RegionId, u64>,
    /// Whether the per-run read control has been reserved yet.
    read_control_reserved: bool,
}

impl DispatchCeiling {
    /// Build the accountant for a declared envelope and run the **feasibility
    /// preflight** (M2). Returns `Err(Feasibility::Infeasible)` without constructing
    /// a runnable ceiling when the envelope cannot fund baseline + controls.
    pub fn new(
        cfg: CeilingConfig,
        envelope: &[crate::RegionId],
    ) -> Result<Self, Feasibility> {
        let required = Self::baseline_plus_controls_cost(&cfg, envelope.len() as u64);
        if required > cfg.ceiling {
            return Err(Feasibility::Infeasible { required, ceiling: cfg.ceiling });
        }
        let unserved_baseline = envelope
            .iter()
            .cloned()
            .map(|r| (r, cfg.baseline_attempts))
            .collect();
        Ok(Self { cfg, reserved: 0, unserved_baseline, read_control_reserved: false })
    }

    /// The preflight cost: every envelope region's baseline probes + their
    /// per-probe write controls, plus the single per-run read control.
    fn baseline_plus_controls_cost(cfg: &CeilingConfig, regions: u64) -> Budget {
        let per_probe = cfg.probe_cost + cfg.write_control_cost;
        regions
            .saturating_mul(cfg.baseline_attempts)
            .saturating_mul(per_probe)
            .saturating_add(cfg.read_control_cost)
    }

    /// Standalone preflight check (acceptance 18) without building the accountant.
    pub fn preflight(cfg: &CeilingConfig, envelope: &[crate::RegionId]) -> Feasibility {
        let required = Self::baseline_plus_controls_cost(cfg, envelope.len() as u64);
        if required > cfg.ceiling {
            Feasibility::Infeasible { required, ceiling: cfg.ceiling }
        } else {
            Feasibility::Ok
        }
    }

    pub fn remaining(&self) -> Budget {
        self.cfg.ceiling.saturating_sub(self.reserved)
    }

    /// Budget still withheld for regions that have not yet received their baseline
    /// (N4): `Σ unserved_baseline × (probe_cost + write_control_cost)`, plus the
    /// per-run read control if not yet reserved.
    pub fn withheld(&self) -> Budget {
        let per_probe = self.cfg.probe_cost + self.cfg.write_control_cost;
        let baseline: Budget = self
            .unserved_baseline
            .values()
            .map(|&n| n.saturating_mul(per_probe))
            .sum();
        let read = if self.read_control_reserved { 0 } else { self.cfg.read_control_cost };
        baseline.saturating_add(read)
    }

    /// The budget a *new* (non-baseline, i.e. intensification) plan may be sized
    /// from: `remaining − withheld` (N4). A region's own baseline draws are exempt
    /// from the withholding (see [`reserve_baseline_probe`]). Never negative.
    ///
    /// [`reserve_baseline_probe`]: Self::reserve_baseline_probe
    pub fn admissible_plan_budget(&self) -> Budget {
        self.remaining().saturating_sub(self.withheld())
    }

    /// Reserve the per-run read control once (idempotent-ish: returns `false` if
    /// already reserved or if it does not fit).
    pub fn reserve_read_control(&mut self) -> bool {
        if self.read_control_reserved {
            return false;
        }
        if self.cfg.read_control_cost > self.remaining() {
            return false;
        }
        self.reserved += self.cfg.read_control_cost;
        self.read_control_reserved = true;
        true
    }

    /// Reserve a **baseline** probe (+ its write control) for a region that still
    /// owes baseline. This draws against `remaining` but is exempt from the
    /// withholding that protects *other* regions. Returns `false` if the region owes
    /// no baseline or the pair does not fit.
    pub fn reserve_baseline_probe(&mut self, region: &crate::RegionId) -> bool {
        let owed = self.unserved_baseline.get(region).copied().unwrap_or(0);
        if owed == 0 {
            return false;
        }
        let cost = self.cfg.probe_cost + self.cfg.write_control_cost;
        if cost > self.remaining() {
            return false;
        }
        self.reserved += cost;
        self.unserved_baseline.insert(region.clone(), owed - 1);
        true
    }

    /// Reserve an **intensification** probe (+ write control). Must fit within
    /// `admissible_plan_budget` — i.e. it may not spend budget withheld for other
    /// regions' baselines (N4). Returns `false` otherwise.
    pub fn reserve_intensification_probe(&mut self) -> bool {
        let cost = self.cfg.probe_cost + self.cfg.write_control_cost;
        if cost > self.admissible_plan_budget() {
            return false;
        }
        self.reserved += cost;
        true
    }

    /// Whether any envelope region still owes baseline probes.
    pub fn baseline_fully_served(&self) -> bool {
        self.unserved_baseline.values().all(|&n| n == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RegionId;

    fn cfg(ceiling: Budget, baseline: u64) -> CeilingConfig {
        CeilingConfig {
            ceiling,
            probe_cost: 1,
            write_control_cost: 1,
            read_control_cost: 1,
            baseline_attempts: baseline,
        }
    }

    fn regions(n: usize) -> Vec<RegionId> {
        (0..n).map(|i| RegionId(format!("r{i}"))).collect()
    }

    #[test]
    fn preflight_rejects_an_unfundable_envelope() {
        // 3 regions × 2 baseline × (1+1) + 1 read = 13; ceiling 10 → infeasible.
        let c = cfg(10, 2);
        let env = regions(3);
        match DispatchCeiling::preflight(&c, &env) {
            Feasibility::Infeasible { required, ceiling } => {
                assert_eq!(required, 13);
                assert_eq!(ceiling, 10);
            }
            Feasibility::Ok => panic!("should be infeasible"),
        }
        assert!(DispatchCeiling::new(c, &env).is_err());
    }

    #[test]
    fn preflight_accepts_a_fundable_envelope() {
        let c = cfg(20, 2);
        let env = regions(3);
        assert_eq!(DispatchCeiling::preflight(&c, &env), Feasibility::Ok);
        assert!(DispatchCeiling::new(c, &env).is_ok());
    }

    #[test]
    fn baseline_is_withheld_from_intensification() {
        // N4 / acceptance 17: a region producing repeated Fails cannot consume the
        // budget withheld for another region's baseline.
        let c = cfg(20, 2);
        let env = regions(2); // r0, r1
        let mut ceil = DispatchCeiling::new(c, &env).unwrap();
        ceil.reserve_read_control();

        // Serve r0's baseline (2 probes).
        assert!(ceil.reserve_baseline_probe(&env[0]));
        assert!(ceil.reserve_baseline_probe(&env[0]));
        assert!(!ceil.reserve_baseline_probe(&env[0]), "r0 baseline exhausted");

        // r1 still owes baseline → that budget is withheld from intensification.
        assert!(!ceil.baseline_fully_served());
        let before = ceil.admissible_plan_budget();
        // Withheld covers r1's 2 probes × 2 = 4. remaining = 20-1-4=15; withheld=4;
        // admissible = 11. Intensification may draw only from admissible.
        assert_eq!(ceil.withheld(), 4);
        assert_eq!(before, ceil.remaining() - 4);

        // Drain admissible with intensification; r1's baseline stays protected.
        let mut draws = 0;
        while ceil.reserve_intensification_probe() {
            draws += 1;
        }
        assert!(draws > 0);
        // r1 can still get its baseline afterwards — it was never spendable.
        assert!(ceil.reserve_baseline_probe(&env[1]));
        assert!(ceil.reserve_baseline_probe(&env[1]));
        assert!(ceil.baseline_fully_served());
    }

    #[test]
    fn never_exceeds_the_ceiling() {
        // Acceptance 5: reservations never exceed the ceiling.
        let c = cfg(6, 1);
        let env = regions(1);
        let mut ceil = DispatchCeiling::new(c, &env).unwrap();
        assert!(ceil.reserve_read_control()); // 1
        assert!(ceil.reserve_baseline_probe(&env[0])); // +2 = 3
        // remaining 3; each intensification pair costs 2.
        assert!(ceil.reserve_intensification_probe()); // +2 = 5
        assert!(!ceil.reserve_intensification_probe(), "would exceed ceiling");
        assert!(ceil.remaining() <= 6 && ceil.remaining() >= 1);
    }
}
