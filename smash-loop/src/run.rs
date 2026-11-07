//! The run body: the resolution **lockstep** ([`reconcile_outcome`]) and the
//! **iteration wrapper** ([`DiscoveryRun`]) that drives the whole P3 §1 loop.
//! Build-order item 3, the final sub-units — this is where every brick meets.
//!
//! ## The lockstep
//!
//! When a dispatched probe resolves, three run-scoped structures must move together or
//! the safety story quietly breaks:
//!
//! - the **quiescence barrier** ([`Quiescence`]) — an unresolved effect must poison the
//!   key + region and raise the barrier (P3 §3.4);
//! - the **dedup table** ([`DedupTable`]) — a clean resolution commits (so later
//!   duplicates merge into it), an *uncertain* one is held so it can never be silently
//!   retried (spec §2.5), in lockstep with the poison above;
//! - the **coverage accumulator** ([`RunAccumulator`]) — the outcome is recorded, and a
//!   poisoned region is annotated so its two-axis coverage shows the `Poisoned` cause.
//!
//! [`reconcile_outcome`] is the single place all three are updated.
//!
//! ## The iteration wrapper
//!
//! [`DiscoveryRun`] ties the proven bricks into the §1 order: propose → admit (with the
//! stage-2 dedup lifecycle) → plan from the withheld budget → dispatch via the
//! [`Controller`] → reconcile → feedback → adjust → steer → conclude. It holds the
//! [`Controller`] (ports + ceiling + quiescence + epochs) alongside the run-scoped state
//! the controller does not own (dedup table, accumulator, the registries admission
//! resolves against, the steering config, and the non-replenishing intensification
//! ledger). Its tests drive it end-to-end with fake ports — no live gate.

use crate::accumulator::RunAccumulator;
use crate::admission::{admit_with_dedup, AdmitOutcome, AdmittedCandidate};
use crate::ceiling::Budget;
use crate::controller::{Controller, StepResult};
use crate::dedup::{DedupTable, ExecutionRef};
use crate::driver::{self, StopSignals};
use crate::epoch::Role;
use crate::feedback::FeedbackAssembler;
use crate::plan::{ControlScope, PlanEntry, ProbeKind};
use crate::quiescence::Quiescence;
use crate::regions::RegionRegistry;
use crate::steering::{self, SteeringConfig};
use crate::stop::{RunOutcome, StopReason};
use crate::verdict::{InconclusiveReason, ProbeOutcome};
use crate::{CanonicalKey, RegionId};
use smash_core::lifecycle::{AttemptState, CleanupOutcome};
use smash_engine::bounds::ParamSpecRegistry;
use smash_engine::registry::Registry;

/// The loop's single bridge from a judged [`ProbeOutcome`] to the core
/// [`AttemptState`] the quiescence barrier consumes.
///
/// A target-induced `Inconclusive(Timeout)` is an **unresolved completion**
/// ([`crate::verdict`]): the effect may still be in flight, so it is `Unresolved` —
/// poison + barrier. Every other outcome reached a judgement (`Pass`/`Fail`, a broken
/// control, an infra `Error` with no in-flight effect), so it is `Resolved`. The real
/// `Dispatcher` therefore surfaces a possibly-in-flight effect as `Inconclusive(Timeout)`,
/// the loop's one unresolved carrier. (A richer `Dispatcher` could instead return the
/// executor's own `AttemptState`; this mapping is the port-preserving path.)
pub fn attempt_state(outcome: ProbeOutcome) -> AttemptState {
    match outcome {
        ProbeOutcome::Inconclusive(InconclusiveReason::Timeout) => AttemptState::Unresolved,
        _ => AttemptState::Resolved,
    }
}

/// Reconcile one resolved probe across all run-scoped state, in lockstep (see the module
/// docs). `execution` is the opaque within-run execution reference that later duplicates
/// of this key merge into (used only on a clean resolution).
///
/// The reservation must already exist (admission reserved it); `commit`/`mark_uncertain`
/// are no-ops otherwise, which keeps this safe to call even on a merged/duplicate path.
#[allow(clippy::too_many_arguments)] // Preserve the kernel's established reconciliation API.
pub fn reconcile_outcome(
    quiescence: &mut Quiescence,
    dedup: &mut DedupTable,
    accumulator: &mut RunAccumulator,
    key: &CanonicalKey,
    region: &RegionId,
    outcome: ProbeOutcome,
    execution: ExecutionRef,
    tick: u64,
) {
    // 1. Coverage: record the dispatched outcome.
    accumulator.record_outcome(region, key, outcome);

    // 2. Barrier: only an Unresolved effect poisons and raises it.
    let state = attempt_state(outcome);
    let unresolved = matches!(state, AttemptState::Unresolved);
    quiescence.record_attempt(state, key.clone(), region.clone(), tick);

    // 3. Dedup + coverage annotation, matching the barrier decision.
    if unresolved {
        accumulator.set_poisoned(region);
        dedup.mark_uncertain(key); // held forever — never silently retried (§2.5)
    } else {
        dedup.commit(key, execution); // resolved — later duplicates merge into it
    }
}

/// The run-level knobs the wrapper needs beyond the [`Controller`]'s own ceiling config.
#[derive(Clone, Debug)]
pub struct DiscoveryConfig {
    pub steering: SteeringConfig,
    /// Cost of one probe dispatch (must match the ceiling's).
    pub probe_cost: Budget,
    /// Cost of one per-probe write control (must match the ceiling's).
    pub write_control_cost: Budget,
    /// The non-replenishing intensification ledger, sized once at run start
    /// (`intensification_share`, P3 §3.5). Drawn only after a region's baseline is served.
    pub intensification_budget: Budget,
    /// Hard iteration cap (P3 §3.1).
    pub max_iterations: u64,
}

/// The autonomous discovery loop. Owns the [`Controller`] plus the run-scoped state the
/// controller does not: the dedup table, the coverage accumulator, the registries
/// admission resolves against, the steering config, and the intensification ledger.
pub struct DiscoveryRun<'a> {
    pub controller: Controller<'a>,
    pub regions: RegionRegistry,
    pub engine_registry: Registry,
    pub param_specs: ParamSpecRegistry,
    pub dedup: DedupTable,
    pub accumulator: RunAccumulator,
    pub feedback: FeedbackAssembler,
    cfg: DiscoveryConfig,
    intensification_remaining: Budget,
    tick: u64,
    ordinal: u64,
}

impl<'a> DiscoveryRun<'a> {
    pub fn new(
        controller: Controller<'a>,
        regions: RegionRegistry,
        engine_registry: Registry,
        param_specs: ParamSpecRegistry,
        accumulator: RunAccumulator,
        cfg: DiscoveryConfig,
    ) -> Self {
        let intensification_remaining = cfg.intensification_budget;
        DiscoveryRun {
            controller,
            regions,
            engine_registry,
            param_specs,
            dedup: DedupTable::new(),
            accumulator,
            feedback: FeedbackAssembler,
            cfg,
            intensification_remaining,
            tick: 0,
            ordinal: 0,
        }
    }

    /// Drive the loop to a terminal [`RunOutcome`]. Reserves the per-run read control
    /// once (its budget is part of the plan roster), then iterates until a stop
    /// condition holds or `max_iterations` is reached.
    pub fn run(&mut self) -> RunOutcome {
        // The per-run read-reachability control's budget is reserved once (M1).
        let _ = self.controller.ceiling.reserve_read_control();
        let mut iteration = 0u64;
        loop {
            if let Some(outcome) = self.step(iteration) {
                return outcome;
            }
            iteration += 1;
            if iteration >= self.cfg.max_iterations {
                return self.conclude_now(StopReason::MaxIterations);
            }
        }
    }

    /// One iteration of the P3 §1 loop. Returns `Some(outcome)` when a stop condition
    /// holds, else `None` to continue.
    fn step(&mut self, iteration: u64) -> Option<RunOutcome> {
        // 1. Propose (owned batch; the borrow of the generator ends here).
        let proposals = self.controller.generator.propose();

        // 2. Admit each (stage-2 dedup lifecycle) and dispatch the admitted ones.
        for proposal in &proposals {
            self.ordinal += 1;
            let provenance = format!("i{iteration}-o{}", self.ordinal);
            let admitted = admit_with_dedup(
                &self.regions,
                &self.engine_registry,
                &self.param_specs,
                &self.controller.quiescence,
                &mut self.dedup,
                proposal,
                provenance,
            );
            match admitted {
                AdmitOutcome::Admitted(adm) => {
                    if let Some(halt) = self.dispatch_admitted(adm) {
                        return Some(halt);
                    }
                }
                // A plan-level denial is counted, never an attempt (N3).
                AdmitOutcome::Denied(_) => self.accumulator.record_denial(&proposal.intended_region),
                // A duplicate (merged) or a poisoned drop does not dispatch.
                AdmitOutcome::Merged(_) | AdmitOutcome::DroppedPoisoned => {}
            }
        }

        // 3. Feedback → adjust (the only channel into the strategy; P3 §2.1).
        let feedback = self.accumulator.typed_feedback(&self.feedback);
        self.controller.generator.adjust(&feedback);

        // 4. Steer: apply new throttles (sticky), read the abort signal.
        let decision = steering::decide(&self.cfg.steering, &self.accumulator.observations());
        for region in &decision.throttle_now {
            self.accumulator.set_throttled(region);
        }

        // 5. Advance the clock and check the stop conditions (P3 §4.3 precedence).
        self.tick += 1;
        self.controller.tick(self.tick);
        let signals = StopSignals {
            quiescence_aborted: self.controller.quiescence.is_aborted(),
            gap_tolerance_exceeded: decision.abort,
            all_regions_sample_resolved: self.accumulator.all_regions_sample_resolved(),
            ..Default::default()
        };
        driver::conclude(
            &signals,
            &self.accumulator.all_coverage(),
            self.accumulator.any_confirmed_fail(),
            CleanupOutcome::Clean,
        )
    }

    /// Plan and dispatch one admitted candidate: size it against the ceiling (baseline
    /// first, then the share-capped intensification ledger), dispatch its per-probe write
    /// control and the probe through the controller, and reconcile the probe's outcome.
    /// Returns `Some(outcome)` if a dispatch halted the run.
    fn dispatch_admitted(&mut self, adm: AdmittedCandidate) -> Option<RunOutcome> {
        // Baseline is withheld and exempt; intensification draws from the admissible
        // budget AND the non-replenishing share ledger (P3 §3.5).
        let pair_cost = self.cfg.probe_cost + self.cfg.write_control_cost;
        let kind = if self.controller.ceiling.reserve_baseline_probe(&adm.region.region) {
            ProbeKind::Baseline
        } else if self.intensification_remaining >= pair_cost
            && self.controller.ceiling.reserve_intensification_probe()
        {
            self.intensification_remaining -= pair_cost;
            ProbeKind::Intensification
        } else {
            // Does not fit — defer whole; release the reservation so it may be
            // re-proposed later (a clean pre-dispatch release, spec §2.5).
            self.dedup.release(&adm.key);
            return None;
        };

        // Dispatch the per-probe write control first (M1: the atomic unit).
        let control = PlanEntry::Control {
            scope: ControlScope::PerProbe,
            backs: Some(adm.key.clone()),
            role: Role::WriteControl,
            cost: self.cfg.write_control_cost,
        };
        match self.controller.run_entry(&control) {
            StepResult::Halt(reason) => return Some(self.conclude_now(reason)),
            StepResult::BarrierBlocked => {
                self.dedup.release(&adm.key);
                return None;
            }
            _ => {}
        }

        // Then the probe.
        let probe = PlanEntry::Probe {
            key: adm.key.clone(),
            region: adm.region.region.clone(),
            kind,
            cost: self.cfg.probe_cost,
        };
        match self.controller.run_entry(&probe) {
            StepResult::Halt(reason) => Some(self.conclude_now(reason)),
            StepResult::BarrierBlocked => {
                self.dedup.release(&adm.key);
                None
            }
            StepResult::Dispatched { outcome } => {
                self.ordinal += 1;
                let execution = format!("exec-{}", self.ordinal);
                reconcile_outcome(
                    &mut self.controller.quiescence,
                    &mut self.dedup,
                    &mut self.accumulator,
                    &adm.key,
                    &adm.region.region,
                    outcome,
                    execution,
                    self.tick,
                );
                None
            }
            StepResult::Idle => None,
        }
    }

    /// Assemble the terminal outcome for a given stop reason (verdict-only exit +
    /// completeness, P3 §4.2), via the controller's `finish`.
    fn conclude_now(&self, reason: StopReason) -> RunOutcome {
        let completeness = crate::coverage::completeness(&self.accumulator.all_coverage());
        self.controller.finish(
            reason,
            self.accumulator.any_confirmed_fail(),
            completeness,
            CleanupOutcome::Clean,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceiling::{CeilingConfig, DispatchCeiling};
    use crate::coverage::Completeness;
    use crate::epoch::{DispatchContext, EpochAllocator};
    use crate::ports::{
        Admission, AdmissionDenial, CandidateProposal, Dispatcher, FixtureProvisioner, Generator,
        KillSwitch, Oracle, ResetError,
    };
    use crate::feedback::TypedFeedback;
    use crate::quiescence::ClearProof;
    use crate::regions::{RegionPartition, RegionRegistry};
    use crate::stop::{ExitCode, StopReason};
    use smash_core::capability::{Authority, RunId};
    use smash_core::correlation::SessionId;
    use smash_core::fighter::{
        EvidenceSchema, FighterId, OracleId, OracleKind, OracleRef, OracleVersion, Prerequisite,
        Technique, TechniqueName,
    };
    use smash_core::lifecycle::RunState;
    use smash_engine::bounds::ParamSpecRegistry;
    use smash_engine::registry::{ApprovedTechnique, Registry, TechniqueHandle, TechniqueVersion};
    use smash_generator::candidate::ParamValue;
    use std::collections::BTreeMap;

    // ── Fixtures (the one technique, its handle, registries) ──────────────

    fn handle() -> TechniqueHandle {
        TechniqueHandle::new(FighterId::new("taint-launder"), TechniqueName::new("encoding-equiv"))
    }

    fn technique() -> Technique {
        Technique::new(
            TechniqueName::new("encoding-equiv"),
            Authority::Mutating,
            OracleRef::new(OracleKind::Differential, OracleId::new("f-b-taint-oracle"), OracleVersion(1)),
            vec![Prerequisite::CanaryBackend],
            EvidenceSchema::new("differential-pair", 1),
            "encoding-laundering of a tainted field",
        )
    }

    struct FullImpl {
        fighter: FighterId,
        declared: Technique,
    }
    impl ApprovedTechnique for FullImpl {
        fn fighter_id(&self) -> &FighterId {
            &self.fighter
        }
        fn technique_name(&self) -> &TechniqueName {
            self.declared.name()
        }
        fn version(&self) -> TechniqueVersion {
            TechniqueVersion(1)
        }
        fn declares(&self) -> &Technique {
            &self.declared
        }
    }

    fn engine_registry() -> Registry {
        let mut reg = Registry::new();
        reg.register(Box::new(FullImpl {
            fighter: FighterId::new("taint-launder"),
            declared: technique(),
        }))
        .unwrap();
        reg
    }

    /// One region `r0` with adequacy 1 — a single resolved probe saturates it.
    fn region_registry() -> RegionRegistry {
        let mut rr = RegionRegistry::new();
        rr.declare(handle(), RegionPartition::new().with_region(RegionId("r0".into()), 1));
        rr
    }

    fn accumulator() -> RunAccumulator {
        RunAccumulator::new(BTreeMap::from([(RegionId("r0".into()), 1u64)]))
    }

    fn proposal() -> CandidateProposal {
        let mut params = BTreeMap::new();
        params.insert("recipient".to_string(), ParamValue::Str("landlord".into()));
        CandidateProposal {
            key: CanonicalKey("advisory".into()),
            handle: handle(),
            intended_region: RegionId("r0".into()),
            params,
        }
    }

    // ── Mock ports ────────────────────────────────────────────────────────

    /// Proposes its batch once, then nothing.
    struct SeededGen {
        batch: Vec<CandidateProposal>,
        done: bool,
    }
    impl Generator for SeededGen {
        fn propose(&mut self) -> Vec<CandidateProposal> {
            if self.done {
                vec![]
            } else {
                self.done = true;
                self.batch.clone()
            }
        }
        fn adjust(&mut self, _f: &TypedFeedback) {}
    }

    // The real admission is `admit_with_dedup`; the Controller's `admission` field is
    // unused by the wrapper, so a never-called stub satisfies the type.
    struct UnusedAdmission;
    impl Admission for UnusedAdmission {
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
        fn try_clear_proof(&mut self, _k: &CanonicalKey) -> Option<ClearProof> {
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

    fn ceiling() -> DispatchCeiling {
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

    fn config() -> DiscoveryConfig {
        DiscoveryConfig {
            steering: SteeringConfig {
                attempted_probe_floor: 1,
                suppression_cap: 1.0,
                gap_tolerance: 1.0,
                gap_floor: 1_000,
            },
            probe_cost: 1,
            write_control_cost: 1,
            intensification_budget: 10,
            max_iterations: 50,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn controller<'a>(
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
            ceiling: ceiling(),
            quiescence: Quiescence::new(3),
            epochs: EpochAllocator::new(42, RunId::new("run-1"), SessionId::new("sess-1")),
            max_iterations: 50,
        }
    }

    #[test]
    fn run_completes_on_earned_saturation() {
        let (mut g, mut a, mut p, mut d, o, k) = (
            SeededGen { batch: vec![proposal()], done: false },
            UnusedAdmission,
            OkProvisioner,
            FixedDispatcher(ProbeOutcome::Pass),
            PassthroughOracle,
            Kill(false),
        );
        let c = controller(&mut g, &mut a, &mut p, &mut d, &o, &k);
        let mut run = DiscoveryRun::new(c, region_registry(), engine_registry(), ParamSpecRegistry::new(), accumulator(), config());
        let out = run.run();
        assert_eq!(out.reason, StopReason::AllRegionsSampleResolved);
        assert_eq!(out.terminal_state, RunState::Completed);
        assert_eq!(out.exit_code, ExitCode::NoConfirmedFailure);
        assert_eq!(out.completeness, Completeness::Complete);
        // Exactly one probe dispatched into r0.
        let obs = run.accumulator.observations();
        assert_eq!(obs.iter().find(|o| o.region == RegionId("r0".into())).unwrap().attempts, 1);
    }

    #[test]
    fn a_confirmed_fail_exits_1() {
        let (mut g, mut a, mut p, mut d, o, k) = (
            SeededGen { batch: vec![proposal()], done: false },
            UnusedAdmission,
            OkProvisioner,
            FixedDispatcher(ProbeOutcome::Fail),
            PassthroughOracle,
            Kill(false),
        );
        let c = controller(&mut g, &mut a, &mut p, &mut d, &o, &k);
        let mut run = DiscoveryRun::new(c, region_registry(), engine_registry(), ParamSpecRegistry::new(), accumulator(), config());
        let out = run.run();
        assert_eq!(out.exit_code, ExitCode::ConfirmedFailure);
        assert!(run.accumulator.any_confirmed_fail());
    }

    #[test]
    fn the_kill_switch_halts_the_run() {
        let (mut g, mut a, mut p, mut d, o, k) = (
            SeededGen { batch: vec![proposal()], done: false },
            UnusedAdmission,
            OkProvisioner,
            FixedDispatcher(ProbeOutcome::Pass),
            PassthroughOracle,
            Kill(true),
        );
        let c = controller(&mut g, &mut a, &mut p, &mut d, &o, &k);
        let mut run = DiscoveryRun::new(c, region_registry(), engine_registry(), ParamSpecRegistry::new(), accumulator(), config());
        let out = run.run();
        assert_eq!(out.reason, StopReason::OperatorKill);
        assert_eq!(out.terminal_state, RunState::Aborted);
    }

    #[test]
    fn duplicate_proposals_dispatch_once() {
        // Two identical candidates in one batch: the second recomputes the same key and
        // merges — only one dispatch reaches r0.
        let (mut g, mut a, mut p, mut d, o, k) = (
            SeededGen { batch: vec![proposal(), proposal()], done: false },
            UnusedAdmission,
            OkProvisioner,
            FixedDispatcher(ProbeOutcome::Pass),
            PassthroughOracle,
            Kill(false),
        );
        let c = controller(&mut g, &mut a, &mut p, &mut d, &o, &k);
        let mut run = DiscoveryRun::new(c, region_registry(), engine_registry(), ParamSpecRegistry::new(), accumulator(), config());
        let _ = run.run();
        let obs = run.accumulator.observations();
        assert_eq!(
            obs.iter().find(|o| o.region == RegionId("r0".into())).unwrap().attempts,
            1,
            "a duplicate must not dispatch twice"
        );
    }

    #[test]
    fn an_unassignable_candidate_is_denied_not_dispatched() {
        let mut bad = proposal();
        bad.intended_region = RegionId("nonexistent".into());
        let (mut g, mut a, mut p, mut d, o, k) = (
            SeededGen { batch: vec![bad], done: false },
            UnusedAdmission,
            OkProvisioner,
            FixedDispatcher(ProbeOutcome::Pass),
            PassthroughOracle,
            Kill(false),
        );
        let c = controller(&mut g, &mut a, &mut p, &mut d, &o, &k);
        let mut run = DiscoveryRun::new(c, region_registry(), engine_registry(), ParamSpecRegistry::new(), accumulator(), config());
        let out = run.run();
        // Nothing dispatched into r0; the run ends on the iteration cap, incomplete.
        assert!(!run.accumulator.any_confirmed_fail());
        assert_eq!(out.reason, StopReason::MaxIterations);
    }
}
