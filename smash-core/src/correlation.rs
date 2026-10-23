//! Correlation types: binding a semantic call key to a single execution.
//!
//! The [`CallKey`] from [`capability`] identifies *semantic call content* —
//! `power_move:<tool>:<hex(args_digest)>`. It is deliberately **not** a unique
//! execution identifier: the same tool with the same arguments produces the
//! same key every time it is called, in any run, in any session. That is what
//! makes it useful for matching a probe to the vouch the target gate signs over
//! the same content.
//!
//! It is also exactly why a call key alone must never be accepted as proof that
//! a particular execution produced a particular effect. The spec is blunt about
//! this (§8): *"Bind it to run, attempt, session, and fixture namespace when
//! correlating records; do not accept a receipt from a different execution
//! merely because its call key matches."* Two runs, or two attempts within a
//! run, or a replay against a stale fixture, can all share a call key while
//! referring to completely different executions.
//!
//! This module provides the binding. [`CorrelationKey`] wraps the call key
//! together with the [`RunId`], an [`AttemptId`] (the unique execution id per
//! attempt), a [`SessionId`], and a [`FixtureNamespace`]. Two correlation keys
//! are equal only when *all* of those match, so
//! [`accepts_receipt`](CorrelationKey::accepts_receipt) answers "does this
//! receipt belong to this execution?" honestly — and
//! [`is_call_key_collision`](CorrelationKey::is_call_key_collision) names the
//! dangerous near-miss: same semantic content, different execution.
//!
//! These are pure identifier types. Writing them into a match log, serializing
//! them into an evidence bundle, and reading them back offline are downstream
//! concerns (engine, oracle, cli); core only defines the binding and its
//! equality.
//!
//! [`capability`]: crate::capability

use crate::capability::{CallKey, RunId};
use std::fmt;

/// The unique execution identifier for a single dispatch attempt. Unlike a
/// [`CallKey`], no two attempts ever share one — it is minted per attempt, not
/// derived from call content. This is the field that distinguishes "the same
/// call, fired again" from "the same call, the same firing."
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttemptId(String);

impl AttemptId {
    pub fn new(id: impl Into<String>) -> Self {
        AttemptId(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AttemptId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The session an effect binds to — the same session the target logs against.
/// Attribution-based correlation hinges on this matching what the target
/// recorded.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(String);

impl SessionId {
    pub fn new(id: impl Into<String>) -> Self {
        SessionId(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The unique namespace a run's fixture state lives in. A fresh namespace per
/// run is what stops a replay or a repeated run from borrowing an earlier run's
/// effects: a receipt from one namespace cannot be claimed by another.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FixtureNamespace(String);

impl FixtureNamespace {
    pub fn new(ns: impl Into<String>) -> Self {
        FixtureNamespace(ns.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FixtureNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The full binding that identifies one execution of one call. Equality
/// requires every field to match; a shared [`CallKey`] alone is never enough.
///
/// This is the type a record carries so that a receipt, a vouch, or an
/// observation can be matched back to the exact execution that produced it —
/// and so that a receipt from a *different* execution is rejected even when its
/// call key is identical.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CorrelationKey {
    run: RunId,
    attempt: AttemptId,
    session: SessionId,
    fixture: FixtureNamespace,
    call: CallKey,
}

impl CorrelationKey {
    pub fn new(
        run: RunId,
        attempt: AttemptId,
        session: SessionId,
        fixture: FixtureNamespace,
        call: CallKey,
    ) -> Self {
        CorrelationKey {
            run,
            attempt,
            session,
            fixture,
            call,
        }
    }

    pub fn run(&self) -> &RunId {
        &self.run
    }

    pub fn attempt(&self) -> &AttemptId {
        &self.attempt
    }

    pub fn session(&self) -> &SessionId {
        &self.session
    }

    pub fn fixture(&self) -> &FixtureNamespace {
        &self.fixture
    }

    pub fn call(&self) -> &CallKey {
        &self.call
    }

    /// Whether `receipt` refers to the same execution as this key. Requires the
    /// **full** binding to match — run, attempt, session, fixture namespace,
    /// and call key. This is the one correct way to decide that a receipt
    /// belongs here; a matching call key alone must never substitute for it.
    pub fn accepts_receipt(&self, receipt: &CorrelationKey) -> bool {
        self == receipt
    }

    /// Whether `other` is a *call-key collision*: it carries the same semantic
    /// call content (same [`CallKey`]) but refers to a different execution.
    /// This is precisely the case [`accepts_receipt`](Self::accepts_receipt)
    /// rejects — surfacing it lets the engine log "saw a matching call key from
    /// a different execution" rather than silently discarding it.
    pub fn is_call_key_collision(&self, other: &CorrelationKey) -> bool {
        self.call == other.call && self != other
    }
}

impl fmt::Display for CorrelationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // run/attempt/session/fixture/call — enough to tell two executions
        // apart in a log line, without exposing argument content.
        write!(
            f,
            "{}/{}/{}/{}::{}",
            self.run, self.attempt, self.session, self.fixture, self.call
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{ArgsDigest, Authority, Call, Target};

    fn call_key() -> CallKey {
        Call {
            session: "s-1".into(),
            tool: "memory_write".into(),
            args_digest: ArgsDigest([0xab; 32]),
            required: Authority::Mutating,
            target: Target::new("http://127.0.0.1:8019"),
        }
        .key()
    }

    fn key_with(run: &str, attempt: &str, session: &str, fixture: &str) -> CorrelationKey {
        CorrelationKey::new(
            RunId::new(run),
            AttemptId::new(attempt),
            SessionId::new(session),
            FixtureNamespace::new(fixture),
            call_key(),
        )
    }

    #[test]
    fn identical_binding_accepts() {
        let a = key_with("run-1", "att-1", "sess-1", "ns-1");
        let b = key_with("run-1", "att-1", "sess-1", "ns-1");
        assert!(a.accepts_receipt(&b));
        assert!(!a.is_call_key_collision(&b));
    }

    #[test]
    fn same_call_key_different_attempt_is_rejected() {
        // The core §8 trap: the same call fired twice shares a call key but is
        // two distinct executions. The second attempt's receipt must not be
        // accepted for the first.
        let first = key_with("run-1", "att-1", "sess-1", "ns-1");
        let second = key_with("run-1", "att-2", "sess-1", "ns-1");
        assert_eq!(first.call(), second.call(), "call keys do match");
        assert!(!first.accepts_receipt(&second));
        assert!(first.is_call_key_collision(&second));
    }

    #[test]
    fn same_call_key_different_run_is_rejected() {
        let a = key_with("run-1", "att-1", "sess-1", "ns-1");
        let b = key_with("run-2", "att-1", "sess-1", "ns-1");
        assert!(!a.accepts_receipt(&b));
        assert!(a.is_call_key_collision(&b));
    }

    #[test]
    fn same_call_key_different_session_is_rejected() {
        let a = key_with("run-1", "att-1", "sess-1", "ns-1");
        let b = key_with("run-1", "att-1", "sess-2", "ns-1");
        assert!(!a.accepts_receipt(&b));
        assert!(a.is_call_key_collision(&b));
    }

    #[test]
    fn same_call_key_different_fixture_namespace_is_rejected() {
        // A replay against a stale fixture: same call, different namespace.
        let a = key_with("run-1", "att-1", "sess-1", "ns-1");
        let b = key_with("run-1", "att-1", "sess-1", "ns-2");
        assert!(!a.accepts_receipt(&b));
        assert!(a.is_call_key_collision(&b));
    }

    #[test]
    fn accessors_round_trip() {
        let k = key_with("run-9", "att-9", "sess-9", "ns-9");
        assert_eq!(k.run(), &RunId::new("run-9"));
        assert_eq!(k.attempt(), &AttemptId::new("att-9"));
        assert_eq!(k.session(), &SessionId::new("sess-9"));
        assert_eq!(k.fixture(), &FixtureNamespace::new("ns-9"));
        assert_eq!(k.call(), &call_key());
    }

    #[test]
    fn display_tells_executions_apart() {
        let a = key_with("run-1", "att-1", "sess-1", "ns-1");
        let b = key_with("run-1", "att-2", "sess-1", "ns-1");
        assert_ne!(a.to_string(), b.to_string());
        assert!(a.to_string().starts_with("run-1/att-1/sess-1/ns-1::"));
    }

    #[test]
    fn identifier_display() {
        assert_eq!(AttemptId::new("att-1").to_string(), "att-1");
        assert_eq!(SessionId::new("sess-1").to_string(), "sess-1");
        assert_eq!(FixtureNamespace::new("ns-1").to_string(), "ns-1");
    }
}
