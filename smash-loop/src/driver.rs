//! Item 2 — the run driver: the stop/exit/completeness decision (P3 §4.2, §4.3).
//!
//! The controller ([`crate::controller`]) runs one plan entry at a time. This
//! module is the other half: given the run's current state, it decides **whether
//! the run is over**, and if so assembles the [`RunOutcome`] — the §4.3 stop
//! precedence and the §4.2 verdict-only-exit + separate completeness field.
//!
//! What this is *not*: the adaptive search body (propose/adjust/throttle). That is
//! item 3. This driver is deliberately a pure function of already-evaluated
//! signals and the current region coverage, so the whole termination contract is
//! testable without a strategy, a generator, or a live gate.

use crate::coverage::{completeness, Completeness, RegionCoverage};
use crate::stop::{select_stop, RunOutcome, StopReason};
use smash_core::lifecycle::CleanupOutcome;

/// The already-evaluated stop conditions for the current iteration. Each field is a
/// boolean the controller computes from raw run state (iteration count vs cap,
/// wall-clock vs budget, ceiling remaining, the quiescence barrier, the suppressed
/// fraction vs tolerance, whether every envelope region is sample-resolved, …).
/// Keeping them as booleans here makes the precedence logic a pure, exhaustively
/// testable mapping; computing them from counters is trivial and lives at the call
/// site.
#[derive(Clone, Copy, Debug, Default)]
pub struct StopSignals {
    pub operator_kill: bool,
    pub quiescence_aborted: bool,
    pub failed_reset: bool,
    pub failed_control: bool,
    pub envelope_infeasible: bool,
    pub unrecoverable_error_rate: bool,
    pub dispatch_ceiling_reached: bool,
    pub gap_tolerance_exceeded: bool,
    pub wall_clock_elapsed: bool,
    pub max_iterations_reached: bool,
    /// First-`Fail` stop is configured *and* a `Fail` has been seen (m6).
    pub first_fail_stop: bool,
    pub all_regions_sample_resolved: bool,
    pub no_progress_window_elapsed: bool,
}

impl StopSignals {
    /// The stop reasons currently satisfied, unordered.
    pub fn satisfied(&self) -> Vec<StopReason> {
        let mut v = Vec::new();
        let mut push = |cond: bool, reason: StopReason| {
            if cond {
                v.push(reason);
            }
        };
        push(self.operator_kill, StopReason::OperatorKill);
        push(self.quiescence_aborted, StopReason::QuiescenceAbort);
        push(self.failed_reset, StopReason::FailedReset);
        push(self.failed_control, StopReason::FailedControl);
        push(self.envelope_infeasible, StopReason::EnvelopeInfeasible);
        push(self.unrecoverable_error_rate, StopReason::UnrecoverableErrorRate);
        push(self.dispatch_ceiling_reached, StopReason::DispatchCeilingReached);
        push(self.gap_tolerance_exceeded, StopReason::GapToleranceExceeded);
        push(self.wall_clock_elapsed, StopReason::WallClock);
        push(self.max_iterations_reached, StopReason::MaxIterations);
        push(self.first_fail_stop, StopReason::FirstFailStop);
        push(self.all_regions_sample_resolved, StopReason::AllRegionsSampleResolved);
        push(self.no_progress_window_elapsed, StopReason::NoProgressWindow);
        v
    }

    /// The winning stop reason by §4.3 precedence, or `None` when the run should
    /// keep going.
    pub fn winner(&self) -> Option<StopReason> {
        select_stop(&self.satisfied())
    }
}

/// Decide whether the run is over and, if so, assemble its outcome.
///
/// Returns `None` while the run should continue (no stop condition holds). When a
/// stop condition holds, returns the [`RunOutcome`]: the winning reason's terminal
/// state, the **verdict-only** exit code (`any Fail ⇒ 1, else 2`; P3 §4.2), and the
/// completeness field computed from the region coverage (`complete` iff every
/// region is `sample-resolved`). `any_confirmed_fail` is the run-wide fact that at
/// least one dispatched probe resolved to `Fail`.
pub fn conclude(
    signals: &StopSignals,
    regions: &[RegionCoverage],
    any_confirmed_fail: bool,
    cleanup: CleanupOutcome,
) -> Option<RunOutcome> {
    let reason = signals.winner()?;
    let completeness: Completeness = completeness(regions);
    Some(RunOutcome::new(reason, any_confirmed_fail, completeness, cleanup))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::RegionCoverage;
    use crate::stop::{ExitCode, StopReason};
    use crate::verdict::{InconclusiveReason, ProbeOutcome::*};
    use smash_core::lifecycle::{CleanupOutcome, RunState};

    fn resolved_region() -> RegionCoverage {
        RegionCoverage::compute(&[Pass, Fail], 2, false, 0, false)
    }
    fn gap_region() -> RegionCoverage {
        RegionCoverage::compute(&[Pass, Inconclusive(InconclusiveReason::Timeout)], 2, false, 0, false)
    }

    #[test]
    fn no_signal_means_keep_going() {
        let s = StopSignals::default();
        assert_eq!(s.winner(), None);
        assert!(conclude(&s, &[resolved_region()], false, CleanupOutcome::Clean).is_none());
    }

    #[test]
    fn saturation_without_fail_is_completed_exit2_complete() {
        let s = StopSignals { all_regions_sample_resolved: true, ..Default::default() };
        let out = conclude(&s, &[resolved_region(), resolved_region()], false, CleanupOutcome::Clean).unwrap();
        assert_eq!(out.reason, StopReason::AllRegionsSampleResolved);
        assert_eq!(out.terminal_state, RunState::Completed);
        assert_eq!(out.exit_code, ExitCode::NoConfirmedFailure);
        assert_eq!(out.completeness, Completeness::Complete);
    }

    #[test]
    fn saturation_with_fail_is_exit1() {
        // The §4.2 verdict-only rule: a confirmed Fail ⇒ exit 1 even at clean saturation.
        let s = StopSignals { all_regions_sample_resolved: true, ..Default::default() };
        let out = conclude(&s, &[resolved_region()], true, CleanupOutcome::Clean).unwrap();
        assert_eq!(out.exit_code, ExitCode::ConfirmedFailure);
    }

    #[test]
    fn operator_kill_outranks_saturation() {
        let s = StopSignals {
            operator_kill: true,
            all_regions_sample_resolved: true,
            no_progress_window_elapsed: true,
            ..Default::default()
        };
        let out = conclude(&s, &[resolved_region()], false, CleanupOutcome::Clean).unwrap();
        assert_eq!(out.reason, StopReason::OperatorKill);
        assert_eq!(out.terminal_state, RunState::Aborted);
    }

    #[test]
    fn ceiling_outranks_gap_tolerance() {
        // Precedence #3 (ceiling) beats #4 (gap tolerance).
        let s = StopSignals {
            dispatch_ceiling_reached: true,
            gap_tolerance_exceeded: true,
            ..Default::default()
        };
        assert_eq!(s.winner(), Some(StopReason::DispatchCeilingReached));
    }

    #[test]
    fn a_gap_region_makes_completeness_incomplete() {
        let s = StopSignals { max_iterations_reached: true, ..Default::default() };
        let out = conclude(&s, &[resolved_region(), gap_region()], false, CleanupOutcome::Clean).unwrap();
        assert!(matches!(out.completeness, Completeness::Incomplete { .. }));
        // Non-gating: incomplete + no fail is exit 2, never 0; blocks green CI.
        assert_eq!(out.exit_code, ExitCode::NoConfirmedFailure);
        assert!(out.blocks_green_ci());
    }

    #[test]
    fn quiescence_abort_is_aborted_terminal() {
        let s = StopSignals { quiescence_aborted: true, ..Default::default() };
        let out = conclude(&s, &[gap_region()], false, CleanupOutcome::Clean).unwrap();
        assert_eq!(out.reason, StopReason::QuiescenceAbort);
        assert_eq!(out.terminal_state, RunState::Aborted);
    }

    #[test]
    fn first_fail_stop_when_configured() {
        let s = StopSignals { first_fail_stop: true, ..Default::default() };
        let out = conclude(&s, &[resolved_region()], true, CleanupOutcome::Clean).unwrap();
        assert_eq!(out.reason, StopReason::FirstFailStop);
        assert_eq!(out.terminal_state, RunState::Completed);
        assert_eq!(out.exit_code, ExitCode::ConfirmedFailure);
    }
}
