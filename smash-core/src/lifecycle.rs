//! Lifecycle types: the run state machine and the per-attempt honesty contract.
//!
//! This module models *operational* status — where a run is in its journey and
//! whether a dispatched probe's effects are known. It is deliberately kept
//! **separate from the security verdict** ([`crate::verdict`]): a run can reach
//! `Completed` while carrying `Fail` verdicts, and a run can be `Errored` with
//! no security verdict at all. Conflating the two is how a harness ends up
//! reporting "secure" when it really means "the test crashed."
//!
//! ## Run states
//!
//! A run advances through operational states:
//!
//! ```text
//!   Created → Preflight → Ready → Running → Finalizing → ┬─ Completed
//!                                                        ├─ Aborted
//!                                                        └─ Errored
//! ```
//!
//! with early exits to the terminal states (`Aborted` on cancellation,
//! `Errored` on infrastructure failure) from the non-terminal states. The
//! legal transitions are enumerated in [`RunState::can_advance_to`]; illegal
//! transitions are rejected, not silently tolerated.
//!
//! ## The attempt honesty contract
//!
//! The spec's hardest operational requirement: *"An interrupted attempt with
//! unknown effects remains unresolved and is never silently retried as though
//! it did not execute."* [`AttemptState`] encodes this. Once a probe is
//! [`Dispatched`](AttemptState::Dispatched), it can only become
//! [`Resolved`](AttemptState::Resolved) (effects observed) or
//! [`Unresolved`](AttemptState::Unresolved) (interrupted, effects unknown).
//! There is no path back to [`Intended`](AttemptState::Intended) — the type
//! refuses to let a fired-but-unobserved call be treated as if it never
//! happened. Only an `Intended` attempt (budget reserved, nothing on the wire)
//! is safe to regard as not executed.
//!
//! ## Limits and cleanup
//!
//! [`OperationalLimits`] carries the finite bounds every run sets. The MVP
//! profile is serial and performs no automatic retries of mutating attempts.
//! [`CleanupOutcome`] records whether fixture teardown succeeded; a cleanup
//! failure is an operational error that blocks a green CI result while
//! preserving any established security finding.

use std::fmt;
use std::time::Duration;

// ── Run state machine ──────────────────────────────────────────────────────

/// Where a run is in its operational journey. Separate from the security
/// verdict: this says whether the run *ran*, not whether the target *passed*.
///
/// Forward-compatible: new variants may be added. Match arms must include a
/// wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RunState {
    /// The run exists; configuration is recorded but nothing has been checked.
    Created,
    /// Validating configuration, authorization, scope, and fixture readiness.
    Preflight,
    /// Preflight passed; the run is cleared to dispatch but has not yet started.
    Ready,
    /// Probes are being dispatched and observed.
    Running,
    /// No new dispatches; observing outstanding effects and running cleanup.
    Finalizing,

    /// Terminal: the run did all the work it was configured to do. Security
    /// verdicts (pass or fail) are recorded separately.
    Completed,
    /// Terminal: the run was cancelled before completing its planned work.
    /// Already-dispatched effects were finalized where possible.
    Aborted,
    /// Terminal: an infrastructure failure prevented completion. Says nothing
    /// about the target's security posture.
    Errored,
}

impl RunState {
    /// Whether this is a terminal state (no further transitions allowed).
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            RunState::Completed | RunState::Aborted | RunState::Errored
        )
    }

    /// Whether a transition from `self` to `next` is legal.
    ///
    /// The happy path is `Created → Preflight → Ready → Running → Finalizing →
    /// Completed`. From any non-terminal state the run may be cancelled
    /// (`→ Aborted`) or hit an infrastructure failure (`→ Errored`). `Running`
    /// always routes through `Finalizing` so outstanding effects are observed
    /// and fixtures are cleaned up before a terminal state is reached.
    pub fn can_advance_to(self, next: RunState) -> bool {
        use RunState::*;
        match (self, next) {
            // Happy path.
            (Created, Preflight) => true,
            (Preflight, Ready) => true,
            (Ready, Running) => true,
            (Running, Finalizing) => true,
            (Finalizing, Completed) => true,

            // Cancellation: legal from any non-terminal state. Running routes
            // through Finalizing first (handled above), so a direct
            // Running → Aborted is not offered — cancel sends it to Finalizing.
            (Created, Aborted) => true,
            (Preflight, Aborted) => true,
            (Ready, Aborted) => true,
            (Finalizing, Aborted) => true,

            // Infrastructure failure: legal from any non-terminal state.
            (Created, Errored) => true,
            (Preflight, Errored) => true,
            (Ready, Errored) => true,
            (Running, Errored) => true,
            (Finalizing, Errored) => true,

            // Everything else — including any transition out of a terminal
            // state, and skipping Finalizing from Running — is illegal.
            _ => false,
        }
    }

    /// Attempt to advance to `next`, returning the new state or an
    /// [`IllegalTransition`] describing the rejected move.
    pub fn try_advance(self, next: RunState) -> Result<RunState, IllegalTransition> {
        if self.can_advance_to(next) {
            Ok(next)
        } else {
            Err(IllegalTransition { from: self, to: next })
        }
    }
}

impl fmt::Display for RunState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            RunState::Created => "created",
            RunState::Preflight => "preflight",
            RunState::Ready => "ready",
            RunState::Running => "running",
            RunState::Finalizing => "finalizing",
            RunState::Completed => "completed",
            RunState::Aborted => "aborted",
            RunState::Errored => "errored",
        };
        f.write_str(s)
    }
}

/// A rejected run-state transition. Loggable, like a denial — a refused move
/// is a fact worth recording, not a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IllegalTransition {
    pub from: RunState,
    pub to: RunState,
}

impl fmt::Display for IllegalTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "illegal run-state transition: {} → {}", self.from, self.to)
    }
}

impl std::error::Error for IllegalTransition {}

// ── Per-attempt honesty contract ────────────────────────────────────────────

/// The resolution status of a single dispatch attempt.
///
/// This is the type-level enforcement of the spec's honesty requirement: a
/// probe that has been put on the wire can never be treated as though it did
/// not execute. The only safe "did not execute" state is [`Intended`] — budget
/// reserved, authorization recorded, nothing dispatched.
///
/// [`Intended`]: AttemptState::Intended
///
/// Forward-compatible: new variants may be added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AttemptState {
    /// Budget reserved and authorization intent recorded, but nothing has been
    /// dispatched. This is the only state safe to regard as "not executed" —
    /// it may be dropped on cancellation with no effect on the target.
    Intended,
    /// The request left the building. Effects may now exist on the target,
    /// whether or not they have been observed.
    Dispatched,
    /// Dispatched and the outcome was observed. Effects are known.
    Resolved,
    /// Dispatched but interrupted before the outcome could be observed. Effects
    /// are unknown. This attempt is **never** retried as if it had not
    /// executed; it is surfaced as unresolved.
    Unresolved,
}

impl AttemptState {
    /// Whether a transition from `self` to `next` is legal.
    ///
    /// `Intended → Dispatched` is the only way onto the wire.
    /// `Dispatched → Resolved | Unresolved` records what happened next.
    /// `Resolved` and `Unresolved` are terminal — crucially, there is no way
    /// back to `Intended`, so a fired call can never be relabelled as
    /// never-executed.
    pub fn can_advance_to(self, next: AttemptState) -> bool {
        use AttemptState::*;
        matches!(
            (self, next),
            (Intended, Dispatched) | (Dispatched, Resolved) | (Dispatched, Unresolved)
        )
    }

    /// Attempt to advance, returning the new state or the rejected move.
    pub fn try_advance(self, next: AttemptState) -> Result<AttemptState, IllegalAttemptTransition> {
        if self.can_advance_to(next) {
            Ok(next)
        } else {
            Err(IllegalAttemptTransition { from: self, to: next })
        }
    }

    /// Whether this attempt may be safely treated as never having executed.
    /// True only for [`Intended`](AttemptState::Intended): no bytes left the
    /// building, so there is no effect to account for. Everything else — even
    /// `Unresolved` — must be accounted for, not assumed away.
    pub fn is_safe_as_not_executed(self) -> bool {
        matches!(self, AttemptState::Intended)
    }

    /// Whether this attempt has reached a terminal resolution.
    pub fn is_resolved_terminal(self) -> bool {
        matches!(self, AttemptState::Resolved | AttemptState::Unresolved)
    }
}

impl fmt::Display for AttemptState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            AttemptState::Intended => "intended",
            AttemptState::Dispatched => "dispatched",
            AttemptState::Resolved => "resolved",
            AttemptState::Unresolved => "unresolved",
        };
        f.write_str(s)
    }
}

/// A rejected attempt-state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IllegalAttemptTransition {
    pub from: AttemptState,
    pub to: AttemptState,
}

impl fmt::Display for IllegalAttemptTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "illegal attempt-state transition: {} → {}",
            self.from, self.to
        )
    }
}

impl std::error::Error for IllegalAttemptTransition {}

// ── Operational limits ──────────────────────────────────────────────────────

/// The finite bounds a run sets before it starts. Pure configuration data;
/// enforcement lives in the engine, but the limits are a domain concept so they
/// live here where the match log and replay contract can see them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalLimits {
    /// Maximum number of requests the run may dispatch.
    pub max_requests: u32,
    /// Wall-clock ceiling for the whole run.
    pub max_duration: Duration,
    /// Maximum concurrent in-flight dispatches. MVP uses `1` (serial).
    pub max_concurrency: u32,
    /// Maximum bytes accepted from a single target response. Bounds the blast
    /// radius of a hostile or runaway response.
    pub max_response_bytes: u64,
    /// Whether a mutating attempt may be automatically retried. MVP: `false`.
    /// A mutating retry risks double-applying an effect, so it is opt-in and
    /// off by default.
    pub retry_mutating: bool,
}

impl OperationalLimits {
    /// The MVP profile: serial execution, no automatic retries of mutating
    /// attempts. Callers supply the quantitative bounds; the safety-shaped
    /// defaults (`max_concurrency = 1`, `retry_mutating = false`) are fixed.
    pub fn mvp(max_requests: u32, max_duration: Duration, max_response_bytes: u64) -> Self {
        OperationalLimits {
            max_requests,
            max_duration,
            max_concurrency: 1,
            max_response_bytes,
            retry_mutating: false,
        }
    }

    /// Whether these limits describe serial execution.
    pub fn is_serial(&self) -> bool {
        self.max_concurrency <= 1
    }
}

// ── Cleanup outcome ─────────────────────────────────────────────────────────

/// The result of fixture teardown. Cleanup runs on both normal completion and
/// failure; crash recovery identifies abandoned resources out of band.
///
/// Forward-compatible: new variants may be added.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CleanupOutcome {
    /// Fixtures were torn down successfully; no resources left behind.
    Clean,
    /// Teardown failed. This is an operational error, not a security finding:
    /// it blocks a green CI result but does **not** erase an established
    /// security verdict.
    Failed {
        /// What could not be cleaned up.
        detail: String,
    },
}

impl CleanupOutcome {
    /// Whether this outcome blocks a green CI result. A cleanup failure does,
    /// because leftover state can poison the next run; a clean teardown does
    /// not.
    pub fn blocks_green_ci(&self) -> bool {
        matches!(self, CleanupOutcome::Failed { .. })
    }
}

impl fmt::Display for CleanupOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CleanupOutcome::Clean => f.write_str("cleanup clean"),
            CleanupOutcome::Failed { detail } => write!(f, "cleanup failed: {detail}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RunState happy path ──────────────────────────────────────────

    #[test]
    fn happy_path_is_legal() {
        let path = [
            RunState::Created,
            RunState::Preflight,
            RunState::Ready,
            RunState::Running,
            RunState::Finalizing,
            RunState::Completed,
        ];
        for pair in path.windows(2) {
            assert!(
                pair[0].can_advance_to(pair[1]),
                "{} → {} should be legal",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn try_advance_returns_next_on_legal() {
        let s = RunState::Created.try_advance(RunState::Preflight).unwrap();
        assert_eq!(s, RunState::Preflight);
    }

    #[test]
    fn try_advance_errors_on_illegal() {
        let err = RunState::Created
            .try_advance(RunState::Completed)
            .unwrap_err();
        assert_eq!(err.from, RunState::Created);
        assert_eq!(err.to, RunState::Completed);
    }

    // ── RunState terminal invariants ─────────────────────────────────

    #[test]
    fn terminal_states_are_terminal() {
        assert!(RunState::Completed.is_terminal());
        assert!(RunState::Aborted.is_terminal());
        assert!(RunState::Errored.is_terminal());
        assert!(!RunState::Running.is_terminal());
    }

    #[test]
    fn no_transitions_out_of_terminal() {
        let terminals = [RunState::Completed, RunState::Aborted, RunState::Errored];
        let all = [
            RunState::Created,
            RunState::Preflight,
            RunState::Ready,
            RunState::Running,
            RunState::Finalizing,
            RunState::Completed,
            RunState::Aborted,
            RunState::Errored,
        ];
        for &t in &terminals {
            for &next in &all {
                assert!(
                    !t.can_advance_to(next),
                    "terminal {t} should not advance to {next}"
                );
            }
        }
    }

    #[test]
    fn running_cannot_skip_finalizing() {
        // Running must route through Finalizing so outstanding effects are
        // observed; it cannot jump straight to a completed/aborted terminal.
        assert!(!RunState::Running.can_advance_to(RunState::Completed));
        assert!(!RunState::Running.can_advance_to(RunState::Aborted));
        // But an infrastructure failure can terminate Running directly.
        assert!(RunState::Running.can_advance_to(RunState::Errored));
    }

    #[test]
    fn cancellation_legal_from_nonterminal_except_running() {
        assert!(RunState::Created.can_advance_to(RunState::Aborted));
        assert!(RunState::Preflight.can_advance_to(RunState::Aborted));
        assert!(RunState::Ready.can_advance_to(RunState::Aborted));
        assert!(RunState::Finalizing.can_advance_to(RunState::Aborted));
    }

    #[test]
    fn errored_legal_from_every_nonterminal() {
        for s in [
            RunState::Created,
            RunState::Preflight,
            RunState::Ready,
            RunState::Running,
            RunState::Finalizing,
        ] {
            assert!(s.can_advance_to(RunState::Errored), "{s} → errored");
        }
    }

    #[test]
    fn no_backward_transitions() {
        assert!(!RunState::Running.can_advance_to(RunState::Ready));
        assert!(!RunState::Ready.can_advance_to(RunState::Created));
        assert!(!RunState::Finalizing.can_advance_to(RunState::Running));
    }

    #[test]
    fn run_state_display() {
        assert_eq!(RunState::Created.to_string(), "created");
        assert_eq!(RunState::Finalizing.to_string(), "finalizing");
        assert_eq!(RunState::Errored.to_string(), "errored");
    }

    // ── AttemptState honesty contract ────────────────────────────────

    #[test]
    fn attempt_happy_path() {
        assert!(AttemptState::Intended.can_advance_to(AttemptState::Dispatched));
        assert!(AttemptState::Dispatched.can_advance_to(AttemptState::Resolved));
        assert!(AttemptState::Dispatched.can_advance_to(AttemptState::Unresolved));
    }

    #[test]
    fn dispatched_can_never_become_intended() {
        // The core honesty invariant: a fired call cannot be relabelled as
        // never-executed.
        assert!(!AttemptState::Dispatched.can_advance_to(AttemptState::Intended));
        assert!(!AttemptState::Unresolved.can_advance_to(AttemptState::Intended));
        assert!(!AttemptState::Resolved.can_advance_to(AttemptState::Intended));
    }

    #[test]
    fn unresolved_is_terminal_and_not_retriable() {
        // Unresolved cannot advance anywhere — in particular not back to
        // Dispatched (a silent retry) or Intended (pretending it never ran).
        for next in [
            AttemptState::Intended,
            AttemptState::Dispatched,
            AttemptState::Resolved,
            AttemptState::Unresolved,
        ] {
            assert!(!AttemptState::Unresolved.can_advance_to(next));
        }
    }

    #[test]
    fn only_intended_is_safe_as_not_executed() {
        assert!(AttemptState::Intended.is_safe_as_not_executed());
        assert!(!AttemptState::Dispatched.is_safe_as_not_executed());
        assert!(!AttemptState::Resolved.is_safe_as_not_executed());
        assert!(!AttemptState::Unresolved.is_safe_as_not_executed());
    }

    #[test]
    fn resolved_terminal_classification() {
        assert!(AttemptState::Resolved.is_resolved_terminal());
        assert!(AttemptState::Unresolved.is_resolved_terminal());
        assert!(!AttemptState::Intended.is_resolved_terminal());
        assert!(!AttemptState::Dispatched.is_resolved_terminal());
    }

    #[test]
    fn attempt_try_advance_errors_carry_the_move() {
        let err = AttemptState::Dispatched
            .try_advance(AttemptState::Intended)
            .unwrap_err();
        assert_eq!(err.from, AttemptState::Dispatched);
        assert_eq!(err.to, AttemptState::Intended);
    }

    #[test]
    fn attempt_state_display() {
        assert_eq!(AttemptState::Intended.to_string(), "intended");
        assert_eq!(AttemptState::Unresolved.to_string(), "unresolved");
    }

    // ── OperationalLimits ────────────────────────────────────────────

    #[test]
    fn mvp_limits_are_serial_with_no_mutating_retry() {
        let limits = OperationalLimits::mvp(100, Duration::from_secs(60), 1 << 20);
        assert_eq!(limits.max_concurrency, 1);
        assert!(!limits.retry_mutating);
        assert!(limits.is_serial());
        assert_eq!(limits.max_requests, 100);
        assert_eq!(limits.max_response_bytes, 1 << 20);
    }

    #[test]
    fn concurrency_above_one_is_not_serial() {
        let limits = OperationalLimits {
            max_requests: 10,
            max_duration: Duration::from_secs(5),
            max_concurrency: 4,
            max_response_bytes: 4096,
            retry_mutating: false,
        };
        assert!(!limits.is_serial());
    }

    // ── CleanupOutcome ───────────────────────────────────────────────

    #[test]
    fn clean_does_not_block_ci() {
        assert!(!CleanupOutcome::Clean.blocks_green_ci());
    }

    #[test]
    fn failed_cleanup_blocks_ci() {
        let outcome = CleanupOutcome::Failed {
            detail: "canary backend still running".into(),
        };
        assert!(outcome.blocks_green_ci());
        assert_eq!(
            outcome.to_string(),
            "cleanup failed: canary backend still running"
        );
    }
}
