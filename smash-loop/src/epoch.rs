//! Deterministic logical epoch + execution identity, built on
//! `smash_core::correlation::CorrelationKey`.
//!
//! Reconciliation note (rev 5 → core): the kernel previously carried its own
//! `ExecutionIdentity` / `PhysicalNamespace` / correlation logic. Core already owns
//! all of it — [`CorrelationKey`] binds run + attempt + session + fixture + call and
//! its `accepts_receipt` / `is_call_key_collision` are exactly the N5/M3 guards. So
//! this module no longer reinvents correlation; it adds only the two things core has
//! no concept of:
//!
//! - the **logical epoch** `(run_seed, dispatch_ordinal)` — a deterministic,
//!   replay-stable tag (finding 3), recorded in the bundle, identical across two
//!   same-seed runs;
//! - a deterministic **allocator** that turns each dispatch into a core
//!   [`AttemptId`] + [`FixtureNamespace`] that embed the run's unique
//!   [`RunId`], so correlation stays unique per run (no receipt-borrowing) while the
//!   logical epoch stays identical for replay.
//!
//! Correlation and replay are different operations with different keys:
//! `CorrelationKey` (run-unique) correlates receipts; [`ReplayTag`] (run-normalized)
//! is what two runs are compared on.

use smash_core::capability::{CallKey, RunId};
use smash_core::correlation::{AttemptId, CorrelationKey, FixtureNamespace, SessionId};

/// Whether a dispatch is a probe or one of its controls (P3 §1 roster, M1).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Role {
    Probe,
    /// Per-run read-reachability control (`v0.3 §7`, amortized once per run).
    ReadControl,
    /// Per-probe positive-write control, in its own namespace/epoch (`v0.3 §7`).
    WriteControl,
}

/// `(run_seed, dispatch_ordinal)` — deterministic, the replay-stable tag. Not part
/// of `CorrelationKey` (which is run-unique); recorded alongside for replay.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct LogicalEpoch {
    pub run_seed: u64,
    pub dispatch_ordinal: u64,
}

/// The run-normalized comparison key for replay (finding 3): the semantic call key,
/// the role, and the logical epoch — with run id, attempt id, fixture namespace all
/// dropped, because those legitimately differ between two runs of the same seed.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ReplayTag {
    pub call: CallKey,
    pub role: Role,
    pub logical: LogicalEpoch,
}

/// Allocates, per dispatch, a deterministic logical epoch and the run-unique core
/// identifiers that make the resulting [`CorrelationKey`] unique to this run.
///
/// The `RunId` is caller-supplied and unique per real run; the `run_seed` is the
/// deterministic seed shared by replays. `AttemptId` and `FixtureNamespace` embed
/// the `RunId`, so two same-seed runs produce identical `LogicalEpoch`s (replay)
/// but distinct `CorrelationKey`s (no borrowing).
#[derive(Debug)]
pub struct EpochAllocator {
    run_seed: u64,
    run_id: RunId,
    session: SessionId,
    next_ordinal: u64,
}

impl EpochAllocator {
    pub fn new(run_seed: u64, run_id: RunId, session: SessionId) -> Self {
        Self { run_seed, run_id, session, next_ordinal: 0 }
    }

    /// Allocate the next dispatch's logical epoch plus its run-unique attempt id and
    /// fixture namespace.
    pub fn allocate(&mut self) -> (LogicalEpoch, AttemptId, FixtureNamespace) {
        let ordinal = self.next_ordinal;
        self.next_ordinal += 1;
        let logical = LogicalEpoch { run_seed: self.run_seed, dispatch_ordinal: ordinal };
        // Run-unique: embeds the unique RunId, so no two runs collide.
        let attempt = AttemptId::new(format!("{}-{ordinal}", self.run_id));
        let fixture = FixtureNamespace::new(format!("{}-{ordinal}", self.run_id));
        (logical, attempt, fixture)
    }

    /// Allocate a full [`DispatchContext`] for one dispatch of the given role. This
    /// is what the controller passes to the provisioner and dispatcher; the
    /// dispatcher completes the [`CorrelationKey`] with the real [`CallKey`] it mints
    /// from the `Call` (the controller cannot fabricate a `CallKey` — core gives it a
    /// private field, mintable only via `Call::key()`).
    pub fn allocate_context(&mut self, role: Role) -> DispatchContext {
        let (logical, attempt, fixture) = self.allocate();
        DispatchContext {
            run_id: self.run_id.clone(),
            session: self.session.clone(),
            attempt,
            fixture,
            logical,
            role,
        }
    }

    /// Build the full correlation key for a dispatch (the run-unique key receipts
    /// correlate on), given the call being made.
    pub fn correlation_key(
        &self,
        attempt: AttemptId,
        fixture: FixtureNamespace,
        call: CallKey,
    ) -> CorrelationKey {
        CorrelationKey::new(self.run_id.clone(), attempt, self.session.clone(), fixture, call)
    }

    pub fn allocated(&self) -> u64 {
        self.next_ordinal
    }
}

/// Everything a dispatch needs except the call key: the run-unique identifiers plus
/// the deterministic logical epoch and the role. The provisioner resets by its
/// `fixture`; the dispatcher completes the [`CorrelationKey`] via [`correlation`].
///
/// [`correlation`]: DispatchContext::correlation
#[derive(Clone, Debug)]
pub struct DispatchContext {
    pub run_id: RunId,
    pub session: SessionId,
    pub attempt: AttemptId,
    pub fixture: FixtureNamespace,
    pub logical: LogicalEpoch,
    pub role: Role,
}

impl DispatchContext {
    /// Complete the run-unique correlation key with the call the dispatcher minted.
    pub fn correlation(&self, call: CallKey) -> CorrelationKey {
        CorrelationKey::new(
            self.run_id.clone(),
            self.attempt.clone(),
            self.session.clone(),
            self.fixture.clone(),
            call,
        )
    }

    /// The run-normalized replay tag for this dispatch (finding 3).
    pub fn replay_tag(&self, call: CallKey) -> ReplayTag {
        ReplayTag { call, role: self.role, logical: self.logical }
    }
}

/// Build the run-normalized replay tag for a dispatch (finding 3): compared across
/// runs, where run id / attempt / fixture legitimately differ.
pub fn replay_tag(call: CallKey, role: Role, logical: LogicalEpoch) -> ReplayTag {
    ReplayTag { call, role, logical }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smash_core::capability::{ArgsDigest, Authority, Call, Target};

    fn call_key(tool: &str) -> CallKey {
        Call {
            session: "s-1".into(),
            tool: tool.into(),
            args_digest: ArgsDigest([0xab; 32]),
            required: Authority::Mutating,
            target: Target::new("http://127.0.0.1:8019"),
        }
        .key()
    }

    fn alloc(run: &str, seed: u64) -> EpochAllocator {
        EpochAllocator::new(seed, RunId::new(run), SessionId::new("sess-1"))
    }

    #[test]
    fn logical_epochs_are_deterministic_across_same_seed_runs() {
        let (mut a, mut b) = (alloc("run-1", 42), alloc("run-2", 42));
        for _ in 0..5 {
            let (la, _, _) = a.allocate();
            let (lb, _, _) = b.allocate();
            assert_eq!(la, lb, "same seed ⇒ identical logical epochs (replay)");
        }
    }

    #[test]
    fn correlation_keys_never_collide_across_runs() {
        // Finding 3 / M3 / core §8: identical logical epoch, different run ⇒ the
        // CorrelationKeys differ, so a receipt from run B is not accepted for run A.
        let (mut a, mut b) = (alloc("run-1", 42), alloc("run-2", 42));
        let (_, aa, af) = a.allocate();
        let (_, ba, bf) = b.allocate();
        let ka = a.correlation_key(aa, af, call_key("web_extract"));
        let kb = b.correlation_key(ba, bf, call_key("web_extract"));
        assert!(!ka.accepts_receipt(&kb), "must not borrow a receipt across runs");
        assert!(ka.is_call_key_collision(&kb), "same call key, different execution");
    }

    #[test]
    fn probe_and_write_control_get_distinct_epochs() {
        let mut a = alloc("run-7", 7);
        let (probe, _, _) = a.allocate();
        let (control, _, _) = a.allocate();
        assert_ne!(probe, control);
    }

    #[test]
    fn replay_tag_is_run_normalized() {
        // Finding 3: two same-seed runs share the normalized replay tag though their
        // correlation keys differ.
        let (mut a, mut b) = (alloc("run-1", 42), alloc("run-2", 42));
        let (la, _, _) = a.allocate();
        let (lb, _, _) = b.allocate();
        let ta = replay_tag(call_key("web_extract"), Role::Probe, la);
        let tb = replay_tag(call_key("web_extract"), Role::Probe, lb);
        assert_eq!(ta, tb);
    }
}
