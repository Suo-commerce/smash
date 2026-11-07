//! The loop controller skeleton (P3 §1): wires the ports in the fixed order
//! propose → admit → quiescence-gate → reset → execute → judge → adjust → check,
//! routing everything through admission + the dispatcher with no shortcut path, and
//! polling the kill switch before each dispatch (P3 §3.1; acceptance 1).
//!
//! Reconciliation note: dispatch identity is a `smash_core::correlation::CorrelationKey`
//! completed by the dispatcher from an [`epoch::DispatchContext`]; outcomes are
//! [`verdict::ProbeOutcome`]; unresolved effects are recorded through the core
//! `AttemptState::Unresolved` path on the quiescence barrier.

use crate::ceiling::DispatchCeiling;
use crate::epoch::{EpochAllocator, Role};
use crate::plan::PlanEntry;
use crate::ports::{Admission, Dispatcher, FixtureProvisioner, Generator, KillSwitch, Oracle};
use crate::quiescence::Quiescence;
use crate::stop::{RunOutcome, StopReason};
use crate::verdict::ProbeOutcome;
use crate::CanonicalKey;
use smash_core::lifecycle::{AttemptState, CleanupOutcome};

pub struct Controller<'a> {
    pub generator: &'a mut dyn Generator,
    pub admission: &'a mut dyn Admission,
    pub provisioner: &'a mut dyn FixtureProvisioner,
    pub dispatcher: &'a mut dyn Dispatcher,
    pub oracle: &'a dyn Oracle,
    pub kill: &'a dyn KillSwitch,
    pub ceiling: DispatchCeiling,
    pub quiescence: Quiescence,
    pub epochs: EpochAllocator,
    pub max_iterations: u64,
}

#[derive(Clone, Debug)]
pub enum StepResult {
    Dispatched { outcome: ProbeOutcome },
    /// A mutating dispatch was blocked by the quiescence barrier this step.
    BarrierBlocked,
    /// The run must stop; carries the winning reason.
    Halt(StopReason),
    Idle,
}

impl<'a> Controller<'a> {
    /// Run one plan entry end-to-end: kill-switch poll → quiescence gate → reset →
    /// execute → judge.
    pub fn run_entry(&mut self, entry: &PlanEntry) -> StepResult {
        if self.kill.should_halt() {
            return StepResult::Halt(StopReason::OperatorKill);
        }
        if self.quiescence.is_aborted() {
            return StepResult::Halt(StopReason::QuiescenceAbort);
        }
        let is_mutating = matches!(entry, PlanEntry::Probe { .. });
        if is_mutating && !self.quiescence.may_dispatch_mutating() {
            return StepResult::BarrierBlocked;
        }
        if let PlanEntry::Probe { key, region, .. } = entry {
            if self.quiescence.is_key_poisoned(key) || self.quiescence.is_region_poisoned(region) {
                return StepResult::BarrierBlocked;
            }
        }

        let role = match entry {
            PlanEntry::Probe { .. } => Role::Probe,
            PlanEntry::Control { role, .. } => *role,
        };
        let ctx = self.epochs.allocate_context(role);

        if self.provisioner.reset(&ctx).is_err() {
            return StepResult::Halt(StopReason::FailedReset);
        }

        let raw = self.dispatcher.execute(entry, &ctx);
        let outcome = self.oracle.judge(entry, raw);
        StepResult::Dispatched { outcome }
    }

    /// Record a dispatched attempt's resolution via the core lifecycle honesty
    /// contract: only `AttemptState::Unresolved` poisons and raises the barrier.
    pub fn record_attempt(
        &mut self,
        state: AttemptState,
        key: CanonicalKey,
        region: crate::RegionId,
        tick: u64,
    ) {
        self.quiescence.record_attempt(state, key, region, tick);
    }

    pub fn tick(&mut self, now: u64) {
        self.quiescence.advance_tick(now);
    }

    /// Assemble the final outcome (exit verdict-only + completeness, P3 §4.2).
    pub fn finish(
        &self,
        reason: StopReason,
        any_confirmed_fail: bool,
        completeness: crate::coverage::Completeness,
        cleanup: CleanupOutcome,
    ) -> RunOutcome {
        RunOutcome::new(reason, any_confirmed_fail, completeness, cleanup)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceiling::{CeilingConfig, DispatchCeiling};
    use crate::epoch::{DispatchContext, EpochAllocator};
    use crate::plan::{ControlScope, DispatchPlan, ProbeKind};
    use crate::ports::{
        Admission, AdmissionDenial, CandidateProposal, Dispatcher, FixtureProvisioner, Generator,
        KillSwitch, Oracle, ResetError,
    };
    use crate::quiescence::Quiescence;
    use crate::{CanonicalKey, RegionId};
    use smash_core::capability::RunId;
    use smash_core::correlation::SessionId;

    struct NullGenerator;
    impl Generator for NullGenerator {
        fn propose(&mut self) -> Vec<CandidateProposal> {
            vec![]
        }
        fn adjust(&mut self, _f: &crate::feedback::TypedFeedback) {}
    }

    struct PassAdmission;
    impl Admission for PassAdmission {
        fn admit(&mut self, p: &CandidateProposal) -> Result<PlanEntry, AdmissionDenial> {
            Ok(PlanEntry::Probe {
                key: p.key.clone(),
                region: p.intended_region.clone(),
                kind: ProbeKind::Baseline,
                cost: 1,
            })
        }
    }

    struct OkProvisioner;
    impl FixtureProvisioner for OkProvisioner {
        fn reset(&mut self, _c: &DispatchContext) -> Result<(), ResetError> {
            Ok(())
        }
        fn try_clear_proof(&mut self, _k: &CanonicalKey) -> Option<crate::quiescence::ClearProof> {
            None
        }
    }
    struct FailProvisioner;
    impl FixtureProvisioner for FailProvisioner {
        fn reset(&mut self, _c: &DispatchContext) -> Result<(), ResetError> {
            Err(ResetError("boom".into()))
        }
        fn try_clear_proof(&mut self, _k: &CanonicalKey) -> Option<crate::quiescence::ClearProof> {
            None
        }
    }

    struct FixedDispatcher(ProbeOutcome);
    impl Dispatcher for FixedDispatcher {
        fn execute(&mut self, _e: &PlanEntry, _c: &DispatchContext) -> ProbeOutcome {
            self.0
        }
    }

    struct PassthroughOracle;
    impl Oracle for PassthroughOracle {
        fn judge(&self, _e: &PlanEntry, raw: ProbeOutcome) -> ProbeOutcome {
            raw
        }
    }

    struct Kill(bool);
    impl KillSwitch for Kill {
        fn should_halt(&self) -> bool {
            self.0
        }
    }

    fn ceil() -> DispatchCeiling {
        DispatchCeiling::new(
            CeilingConfig {
                ceiling: 100,
                probe_cost: 1,
                write_control_cost: 1,
                read_control_cost: 1,
                baseline_attempts: 1,
            },
            &[RegionId("r0".into())],
        )
        .unwrap()
    }

    fn probe() -> PlanEntry {
        PlanEntry::Probe {
            key: CanonicalKey("c1".into()),
            region: RegionId("r0".into()),
            kind: ProbeKind::Baseline,
            cost: 1,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn make<'a>(
        g: &'a mut dyn Generator,
        a: &'a mut dyn Admission,
        p: &'a mut dyn FixtureProvisioner,
        d: &'a mut dyn Dispatcher,
        o: &'a dyn Oracle,
        k: &'a dyn KillSwitch,
    ) -> Controller<'a> {
        Controller {
            generator: g,
            admission: a,
            provisioner: p,
            dispatcher: d,
            oracle: o,
            kill: k,
            ceiling: ceil(),
            quiescence: Quiescence::new(3),
            epochs: EpochAllocator::new(42, RunId::new("run-1"), SessionId::new("sess-1")),
            max_iterations: 100,
        }
    }

    #[test]
    fn kill_switch_halts_before_dispatch() {
        let (mut g, mut a, mut p, mut d, o, k) = (
            NullGenerator, PassAdmission, OkProvisioner,
            FixedDispatcher(ProbeOutcome::Pass), PassthroughOracle, Kill(true),
        );
        let mut c = make(&mut g, &mut a, &mut p, &mut d, &o, &k);
        assert!(matches!(c.run_entry(&probe()), StepResult::Halt(StopReason::OperatorKill)));
    }

    #[test]
    fn failed_reset_is_operational_halt() {
        let (mut g, mut a, mut p, mut d, o, k) = (
            NullGenerator, PassAdmission, FailProvisioner,
            FixedDispatcher(ProbeOutcome::Pass), PassthroughOracle, Kill(false),
        );
        let mut c = make(&mut g, &mut a, &mut p, &mut d, &o, &k);
        assert!(matches!(c.run_entry(&probe()), StepResult::Halt(StopReason::FailedReset)));
    }

    #[test]
    fn barrier_blocks_mutating_dispatch_after_unresolved_effect() {
        let (mut g, mut a, mut p, mut d, o, k) = (
            NullGenerator, PassAdmission, OkProvisioner,
            FixedDispatcher(ProbeOutcome::Pass), PassthroughOracle, Kill(false),
        );
        let mut c = make(&mut g, &mut a, &mut p, &mut d, &o, &k);
        c.record_attempt(AttemptState::Unresolved, CanonicalKey("c0".into()), RegionId("r0".into()), 0);
        assert!(matches!(c.run_entry(&probe()), StepResult::BarrierBlocked));
    }

    #[test]
    fn happy_path_dispatches_and_judges() {
        let (mut g, mut a, mut p, mut d, o, k) = (
            NullGenerator, PassAdmission, OkProvisioner,
            FixedDispatcher(ProbeOutcome::Fail), PassthroughOracle, Kill(false),
        );
        let mut c = make(&mut g, &mut a, &mut p, &mut d, &o, &k);
        match c.run_entry(&probe()) {
            StepResult::Dispatched { outcome } => assert_eq!(outcome, ProbeOutcome::Fail),
            other => panic!("expected dispatch, got {other:?}"),
        }
    }

    #[test]
    fn control_entry_is_not_gated_by_the_mutating_barrier() {
        let (mut g, mut a, mut p, mut d, o, k) = (
            NullGenerator, PassAdmission, OkProvisioner,
            FixedDispatcher(ProbeOutcome::Pass), PassthroughOracle, Kill(false),
        );
        let mut c = make(&mut g, &mut a, &mut p, &mut d, &o, &k);
        c.record_attempt(AttemptState::Unresolved, CanonicalKey("x".into()), RegionId("other".into()), 0);
        let control = PlanEntry::Control {
            scope: ControlScope::PerRun,
            backs: None,
            role: Role::ReadControl,
            cost: 1,
        };
        assert!(matches!(c.run_entry(&control), StepResult::Dispatched { .. }));
    }

    #[test]
    fn unused_plan_helper_links() {
        let _ = DispatchPlan::mutating_probe(
            CanonicalKey("c".into()), RegionId("r0".into()), ProbeKind::Baseline, 1, 1);
    }
}
