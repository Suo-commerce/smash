//! Stopping: terminal state on `smash_core::lifecycle::RunState`, the loop's own
//! non-gating exit rule, the separate completeness field, and stop precedence
//! (P3 §4; acceptance 9).
//!
//! Reconciliation note: terminal state is core's [`RunState`]
//! (`Completed`/`Aborted`/`Errored`), and cleanup reuses core's [`CleanupOutcome`].
//! The exit **rule** stays loop-side and is deliberately *not*
//! `smash_core::verdict::VerdictSummary::exit_code` (which can return 0): a loop run
//! is non-gating and never exits 0 (n7). It reuses the 1/2 *ordering*, not the
//! required-coverage predicate.

use crate::coverage::Completeness;
use smash_core::lifecycle::{CleanupOutcome, RunState};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StopReason {
    OperatorKill,
    QuiescenceAbort,
    FailedReset,
    FailedControl,
    EnvelopeInfeasible,
    UnrecoverableErrorRate,
    DispatchCeilingReached,
    GapToleranceExceeded,
    WallClock,
    MaxIterations,
    FirstFailStop,
    AllRegionsSampleResolved,
    NoProgressWindow,
}

impl StopReason {
    /// First-match-wins precedence (P3 §4.3). Lower = higher priority.
    pub fn precedence(self) -> u8 {
        match self {
            StopReason::OperatorKill => 0,
            StopReason::QuiescenceAbort
            | StopReason::FailedReset
            | StopReason::FailedControl
            | StopReason::EnvelopeInfeasible => 1,
            StopReason::UnrecoverableErrorRate => 2,
            StopReason::DispatchCeilingReached => 3,
            StopReason::GapToleranceExceeded => 4,
            StopReason::WallClock | StopReason::MaxIterations => 5,
            StopReason::FirstFailStop => 6,
            StopReason::AllRegionsSampleResolved => 7,
            StopReason::NoProgressWindow => 8,
        }
    }

    /// The core terminal lifecycle state this halt produces (`v0.3 §9`).
    pub fn terminal_state(self) -> RunState {
        match self {
            StopReason::OperatorKill
            | StopReason::QuiescenceAbort
            | StopReason::FailedReset
            | StopReason::FailedControl
            | StopReason::EnvelopeInfeasible
            | StopReason::GapToleranceExceeded => RunState::Aborted,
            StopReason::UnrecoverableErrorRate => RunState::Errored,
            StopReason::DispatchCeilingReached
            | StopReason::WallClock
            | StopReason::MaxIterations
            | StopReason::FirstFailStop
            | StopReason::AllRegionsSampleResolved
            | StopReason::NoProgressWindow => RunState::Completed,
        }
    }
}

/// The loop's exit code. Only 1 or 2 — never 0 (P3 §4.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExitCode {
    ConfirmedFailure = 1,
    NoConfirmedFailure = 2,
}

#[derive(Clone, Debug)]
pub struct RunOutcome {
    pub terminal_state: RunState,
    pub exit_code: ExitCode,
    pub completeness: Completeness,
    pub reason: StopReason,
    pub cleanup: CleanupOutcome,
}

impl RunOutcome {
    /// Exit is **verdict-only** (P3 §4.2): `any_fail ⇒ 1`, else 2 — regardless of
    /// terminal state or completeness.
    pub fn new(
        reason: StopReason,
        any_confirmed_fail: bool,
        completeness: Completeness,
        cleanup: CleanupOutcome,
    ) -> Self {
        let exit_code = if any_confirmed_fail {
            ExitCode::ConfirmedFailure
        } else {
            ExitCode::NoConfirmedFailure
        };
        Self { terminal_state: reason.terminal_state(), exit_code, completeness, reason, cleanup }
    }

    /// A loop run never produces exit 0; cleanup failure (core `CleanupOutcome`)
    /// blocks green while preserving findings (`v0.3 §9`).
    pub fn blocks_green_ci(&self) -> bool {
        self.cleanup.blocks_green_ci()
            || self.exit_code != ExitCode::NoConfirmedFailure
            || matches!(self.completeness, Completeness::Incomplete { .. })
    }
}

/// Pick the winning stop reason among those satisfied (first-match-wins).
pub fn select_stop(candidates: &[StopReason]) -> Option<StopReason> {
    candidates.iter().copied().min_by_key(|r| r.precedence())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::Completeness;
    use smash_core::lifecycle::{CleanupOutcome, RunState};

    fn incomplete() -> Completeness {
        Completeness::Incomplete { gap_causes: Default::default(), planner_denials_total: 0 }
    }

    #[test]
    fn exit_is_verdict_only_even_on_abort() {
        let out = RunOutcome::new(StopReason::QuiescenceAbort, true, incomplete(), CleanupOutcome::Clean);
        assert_eq!(out.exit_code, ExitCode::ConfirmedFailure);
        assert_eq!(out.terminal_state, RunState::Aborted);
    }

    #[test]
    fn clean_saturation_without_fail_is_exit_2_never_0() {
        let out = RunOutcome::new(
            StopReason::AllRegionsSampleResolved, false, Completeness::Complete, CleanupOutcome::Clean);
        assert_eq!(out.exit_code, ExitCode::NoConfirmedFailure);
        assert_eq!(out.terminal_state, RunState::Completed);
        assert!(!out.blocks_green_ci());
    }

    #[test]
    fn precedence_prefers_operator_kill_over_saturation() {
        let w = select_stop(&[StopReason::AllRegionsSampleResolved, StopReason::OperatorKill, StopReason::NoProgressWindow]);
        assert_eq!(w, Some(StopReason::OperatorKill));
    }

    #[test]
    fn quiescence_abort_outranks_ceiling() {
        let w = select_stop(&[StopReason::DispatchCeilingReached, StopReason::QuiescenceAbort]);
        assert_eq!(w, Some(StopReason::QuiescenceAbort));
    }

    #[test]
    fn cleanup_failure_blocks_green_ci_even_when_complete() {
        let out = RunOutcome::new(
            StopReason::AllRegionsSampleResolved,
            false,
            Completeness::Complete,
            CleanupOutcome::Failed { detail: "canary still up".into() },
        );
        assert!(out.blocks_green_ci());
    }

    #[test]
    fn incomplete_blocks_green_ci() {
        let out = RunOutcome::new(StopReason::MaxIterations, false, incomplete(), CleanupOutcome::Clean);
        assert!(out.blocks_green_ci());
    }
}
