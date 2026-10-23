//! Capability types: Smash's typed scope × authority gate.
//!
//! This is the containment wall from the architecture. It governs what *Smash
//! itself* is permitted to emit in a given match — not the target's security
//! model. The target's authority clamp is the thing a fighter *probes*; this
//! type is the thing that stops Smash from ever stepping off-stage while doing
//! the probing. Keep that distinction sharp: a read-only clamp fighter will
//! often need a match capability that *grants* `Mutating`, because the whole
//! point is to attempt a write the target is supposed to refuse.
//!
//! The core property is *containment by construction*. A raw [`Call`] is inert
//! data. The only way to obtain an [`AuthorizedCall`] — the only thing the
//! engine will dispatch — is to pass a [`Call`] through [`Capability::authorize`].
//! `AuthorizedCall` has no public constructor, so "this call was inside scope
//! and within authority" is a fact the type system carries, not a runtime
//! promise a later refactor can quietly drop.
//!
//! ## Minting versus dispatch
//!
//! There are two gates, and they are deliberately separate:
//!
//! - **Minting** ([`Capability::authorize`]) is the static check: is the call's
//!   target in scope, and is its required authority within the ceiling? Success
//!   stamps the token with the binding fields (run, capability version, expiry)
//!   copied from the capability. These are immutable once minted.
//! - **Dispatch** ([`AuthorizedCall::check_dispatchable`]) is the live check,
//!   applied just before the probe leaves the building: has the token expired,
//!   and is there budget left? The caller injects `now`, so core needs no clock
//!   and the check stays pure and testable. (The engine additionally gates on
//!   run state — only a `Running` run dispatches — using the lifecycle module.)
//!
//! A [`Denial`] from either gate is a replayable fact, not an error to swallow:
//! a denied test is *unexecuted coverage*, never a security pass.
//!
//! ## Immutability within a run
//!
//! A capability carries a [`RunId`] and a [`CapabilityVersion`]. There is no API
//! to raise the ceiling or re-stamp the version: capabilities cannot be upgraded
//! within an existing run. A changed permission is a new capability, with a new
//! version, which the evidence bundle records as a distinct snapshot.
//!
//! This crate is dependency-free (std only). Argument canonicalization and
//! hashing live upstream in `smash-engine`, which speaks the wire envelope
//! (OpenAI-compatible JSON for the first target). The engine hands us a
//! precomputed [`ArgsDigest`]; we define its canonical *key* form so the match
//! log's key and the target gate's vouch key are byte-identical:
//! `power_move:<tool>:<hex(sha256(canonical_json(args)))>`.

use std::collections::BTreeSet;
use std::fmt;
use std::time::SystemTime;

/// What a call is permitted to *do*. Ordered: `ReadOnly < Mutating`.
///
/// A capability grants an authority *ceiling*; a call declares the authority it
/// *requires*. Authorization allows the call iff `required <= ceiling`. The
/// derived `Ord` depends on declaration order — do not reorder these variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Authority {
    /// No observable side effect on the target backend.
    ReadOnly,
    /// May mutate target-side state.
    Mutating,
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Authority::ReadOnly => f.write_str("read-only"),
            Authority::Mutating => f.write_str("mutating"),
        }
    }
}

/// A target stage's identity, canonicalized to an origin (scheme + host + port).
///
/// First target: `http://127.0.0.1:8019` (Storm Gate). Membership is exact-match
/// on this string for now; path-prefix and route scoping come in a later file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Target(String);

impl Target {
    /// Construct from an already-normalized origin. Normalization (lowercasing
    /// host, dropping default ports, stripping trailing slash) is the engine's
    /// job before it reaches here — this type assumes canonical input.
    pub fn new(origin: impl Into<String>) -> Self {
        Target(origin.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A run's stable identifier. The authorization token binds to this, so a token
/// minted for one run can never be replayed to dispatch in another.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RunId(String);

impl RunId {
    pub fn new(id: impl Into<String>) -> Self {
        RunId(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The version of a capability snapshot. Immutable once a capability exists;
/// a changed permission is a new capability with a new version, never an
/// in-place upgrade. The evidence bundle records the version so a verdict is
/// scoped to the exact permission that authorized it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapabilityVersion(pub u32);

impl fmt::Display for CapabilityVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// The allowlist of targets a match may reach. A request to anything not in
/// this set is structurally undispatchable — the gate cannot produce an
/// `AuthorizedCall` for it.
///
/// There is deliberately no wildcard or allow-all constructor: scope is an
/// explicit set of normalized origins, always.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope {
    targets: BTreeSet<Target>,
}

impl Scope {
    pub fn new(targets: impl IntoIterator<Item = Target>) -> Self {
        Scope {
            targets: targets.into_iter().collect(),
        }
    }

    pub fn contains(&self, target: &Target) -> bool {
        self.targets.contains(target)
    }

    pub fn targets(&self) -> impl Iterator<Item = &Target> {
        self.targets.iter()
    }
}

/// What this match authorizes Smash to do: where it may reach, the highest
/// authority it may attempt, and the run / version / expiry binding stamped
/// onto every token it mints. Scope and ceiling are enforced in [`authorize`];
/// expiry is enforced at dispatch.
///
/// [`authorize`]: Capability::authorize
#[derive(Debug, Clone)]
pub struct Capability {
    scope: Scope,
    ceiling: Authority,
    run: RunId,
    version: CapabilityVersion,
    /// The instant after which tokens minted from this capability are no longer
    /// dispatchable. Checked at dispatch, not at mint time.
    expiry: SystemTime,
}

impl Capability {
    pub fn new(
        scope: Scope,
        ceiling: Authority,
        run: RunId,
        version: CapabilityVersion,
        expiry: SystemTime,
    ) -> Self {
        Capability {
            scope,
            ceiling,
            run,
            version,
            expiry,
        }
    }

    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    pub fn ceiling(&self) -> Authority {
        self.ceiling
    }

    pub fn run(&self) -> &RunId {
        &self.run
    }

    pub fn version(&self) -> CapabilityVersion {
        self.version
    }

    pub fn expiry(&self) -> SystemTime {
        self.expiry
    }

    /// The one minting chokepoint. Returns an [`AuthorizedCall`] iff the call's
    /// target is in scope *and* its required authority is within the ceiling.
    /// The resulting token is stamped with this capability's run, version, and
    /// expiry — immutably.
    ///
    /// Expiry and budget are **not** checked here; they are live conditions
    /// checked at dispatch via [`AuthorizedCall::check_dispatchable`]. Minting a
    /// token is cheap and side-effect-free; whether it may *fire* depends on the
    /// state of the run at the moment of dispatch.
    ///
    /// A [`Denial`] is not an error to swallow — it is a replayable fact about
    /// why a probe never left the building, and the match log records it as
    /// such.
    pub fn authorize(&self, call: Call) -> Result<AuthorizedCall, Denial> {
        if !self.scope.contains(&call.target) {
            return Err(Denial::OutOfScope {
                target: call.target,
            });
        }
        if call.required > self.ceiling {
            return Err(Denial::AuthorityExceeded {
                required: call.required,
                ceiling: self.ceiling,
            });
        }
        Ok(AuthorizedCall {
            call,
            run: self.run.clone(),
            version: self.version,
            expiry: self.expiry,
        })
    }
}

/// An inert, unauthorized tool-call probe. Just data until it clears the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// The caller/session the effect must bind to. Attribution kills hinge on
    /// this matching what the target logs.
    pub session: String,
    /// The tool name as it appears in the target's `tools[]` array.
    pub tool: String,
    /// sha256 over the engine's canonical-JSON encoding of the arguments.
    pub args_digest: ArgsDigest,
    /// The authority this call *requires* (e.g. a write tool requires `Mutating`).
    /// This is the token's bound *effect requirement*.
    pub required: Authority,
    /// Where this call is aimed.
    pub target: Target,
}

impl Call {
    /// The canonical key: `power_move:<tool>:<hex(args_digest)>`. Byte-identical
    /// to the target gate's vouch key, so a differential verdict replays
    /// against the same artifact the gate signs.
    ///
    /// Note: the key identifies *semantic call content*, not a unique execution.
    /// Correlating a receipt requires binding the key to run, attempt, session,
    /// and fixture namespace — a matching key alone must never be accepted as
    /// proof that a particular execution produced a particular effect.
    pub fn key(&self) -> CallKey {
        CallKey(format!("power_move:{}:{}", self.tool, self.args_digest.to_hex()))
    }
}

/// A gate-cleared call. The private fields are the whole point: outside this
/// module there is no way to build one except via [`Capability::authorize`].
/// The engine's dispatch entry point takes `AuthorizedCall`, never `Call`.
///
/// The token binds the immutable call (digest + target + effect requirement),
/// the run, the capability version, and the expiry. Because the engine
/// dispatches exactly [`call()`](AuthorizedCall::call), a token can never be
/// reused to send altered bytes or reach a different destination — the bytes
/// and the destination *are* the token.
#[derive(Debug, Clone)]
pub struct AuthorizedCall {
    call: Call,
    run: RunId,
    version: CapabilityVersion,
    expiry: SystemTime,
}

impl AuthorizedCall {
    pub fn call(&self) -> &Call {
        &self.call
    }

    pub fn key(&self) -> CallKey {
        self.call.key()
    }

    /// The run this token is bound to.
    pub fn run(&self) -> &RunId {
        &self.run
    }

    /// The capability version that minted this token.
    pub fn version(&self) -> CapabilityVersion {
        self.version
    }

    /// The instant after which this token may no longer be dispatched.
    pub fn expiry(&self) -> SystemTime {
        self.expiry
    }

    /// The live dispatch gate. Call this immediately before the probe leaves the
    /// building. `now` is injected by the caller (the engine's clock), keeping
    /// core free of any clock of its own and making the check deterministic in
    /// tests.
    ///
    /// Returns [`Denial::Expired`] if `now` is past the token's expiry, or
    /// [`Denial::BudgetExceeded`] if the run has no dispatch budget left. Both
    /// are recorded as facts — a denied dispatch is unexecuted coverage, not a
    /// pass. Run-state gating (dispatch only while `Running`) is layered on by
    /// the engine using the lifecycle module; it is not core's concern here.
    pub fn check_dispatchable(
        &self,
        now: SystemTime,
        remaining_budget: u32,
    ) -> Result<(), Denial> {
        if now > self.expiry {
            return Err(Denial::Expired {
                expiry: self.expiry,
                at: now,
            });
        }
        if remaining_budget == 0 {
            return Err(Denial::BudgetExceeded);
        }
        Ok(())
    }
}

/// Why a call was refused — at the mint gate or the dispatch gate. Loggable and
/// replayable. Each denial is unexecuted coverage, never a security pass.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Denial {
    /// The target is not in the match's scope allowlist. (Mint gate.)
    OutOfScope { target: Target },
    /// The call requires more authority than the capability's ceiling. (Mint
    /// gate.)
    AuthorityExceeded { required: Authority, ceiling: Authority },
    /// The token's expiry has passed. (Dispatch gate.)
    Expired { expiry: SystemTime, at: SystemTime },
    /// The run has exhausted its dispatch budget. (Dispatch gate.)
    BudgetExceeded,
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Denial::OutOfScope { target } => {
                write!(f, "target {target} is not in scope")
            }
            Denial::AuthorityExceeded { required, ceiling } => {
                write!(f, "call requires {required} authority but ceiling is {ceiling}")
            }
            Denial::Expired { .. } => f.write_str("authorization expired"),
            Denial::BudgetExceeded => f.write_str("run dispatch budget exhausted"),
        }
    }
}

impl std::error::Error for Denial {}

/// A 32-byte sha256 digest of canonical-JSON arguments, computed upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArgsDigest(pub [u8; 32]);

impl ArgsDigest {
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for byte in self.0 {
            s.push(nibble(byte >> 4));
            s.push(nibble(byte & 0x0f));
        }
        s
    }
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + (n - 10)) as char,
    }
}

/// The canonical log/vouch key for a call.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallKey(String);

impl CallKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CallKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn storm_gate() -> Target {
        Target::new("http://127.0.0.1:8019")
    }

    fn run() -> RunId {
        RunId::new("run-0001")
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// A capability whose tokens expire at t=1000s.
    fn cap(ceiling: Authority) -> Capability {
        Capability::new(
            Scope::new([storm_gate()]),
            ceiling,
            run(),
            CapabilityVersion(1),
            at(1000),
        )
    }

    fn call(required: Authority, target: Target) -> Call {
        Call {
            session: "s-1".into(),
            tool: "memory_write".into(),
            args_digest: ArgsDigest([0xab; 32]),
            required,
            target,
        }
    }

    // ── Mint gate (scope × authority) ────────────────────────────────

    #[test]
    fn authority_is_ordered() {
        assert!(Authority::ReadOnly < Authority::Mutating);
    }

    #[test]
    fn read_only_ceiling_denies_mutating() {
        let denial = cap(Authority::ReadOnly)
            .authorize(call(Authority::Mutating, storm_gate()))
            .unwrap_err();
        assert_eq!(
            denial,
            Denial::AuthorityExceeded {
                required: Authority::Mutating,
                ceiling: Authority::ReadOnly,
            }
        );
    }

    #[test]
    fn out_of_scope_target_denies() {
        let elsewhere = Target::new("http://127.0.0.1:9999");
        let denial = cap(Authority::Mutating)
            .authorize(call(Authority::ReadOnly, elsewhere.clone()))
            .unwrap_err();
        assert_eq!(denial, Denial::OutOfScope { target: elsewhere });
    }

    #[test]
    fn in_scope_within_authority_clears_and_keys_match() {
        let raw = call(Authority::Mutating, storm_gate());
        let expected = raw.key();
        let authorized = cap(Authority::Mutating).authorize(raw).unwrap();
        // The key survives the gate unchanged — same canonical form in the log.
        assert_eq!(authorized.key(), expected);
        assert_eq!(
            authorized.key().as_str(),
            format!("power_move:memory_write:{}", ArgsDigest([0xab; 32]).to_hex())
        );
    }

    // ── Token binding ────────────────────────────────────────────────

    #[test]
    fn token_binds_run_version_and_expiry() {
        let authorized = cap(Authority::Mutating)
            .authorize(call(Authority::Mutating, storm_gate()))
            .unwrap();
        assert_eq!(authorized.run(), &run());
        assert_eq!(authorized.version(), CapabilityVersion(1));
        assert_eq!(authorized.expiry(), at(1000));
    }

    #[test]
    fn minting_does_not_check_expiry() {
        // A token can be minted even when "now" is already past expiry — expiry
        // is a dispatch-time condition, not a mint-time one. (Here we simply
        // confirm authorize succeeds regardless of wall-clock; the dispatch
        // check is exercised separately.)
        let authorized = cap(Authority::Mutating)
            .authorize(call(Authority::Mutating, storm_gate()));
        assert!(authorized.is_ok());
    }

    // ── Dispatch gate (expiry × budget) ──────────────────────────────

    #[test]
    fn dispatchable_before_expiry_with_budget() {
        let authorized = cap(Authority::Mutating)
            .authorize(call(Authority::Mutating, storm_gate()))
            .unwrap();
        assert!(authorized.check_dispatchable(at(999), 5).is_ok());
    }

    #[test]
    fn expired_token_is_denied() {
        let authorized = cap(Authority::Mutating)
            .authorize(call(Authority::Mutating, storm_gate()))
            .unwrap();
        let denial = authorized.check_dispatchable(at(1001), 5).unwrap_err();
        assert_eq!(
            denial,
            Denial::Expired {
                expiry: at(1000),
                at: at(1001),
            }
        );
    }

    #[test]
    fn expiry_boundary_is_inclusive() {
        // now == expiry is still dispatchable; only now > expiry is expired.
        let authorized = cap(Authority::Mutating)
            .authorize(call(Authority::Mutating, storm_gate()))
            .unwrap();
        assert!(authorized.check_dispatchable(at(1000), 1).is_ok());
    }

    #[test]
    fn zero_budget_is_denied() {
        let authorized = cap(Authority::Mutating)
            .authorize(call(Authority::Mutating, storm_gate()))
            .unwrap();
        let denial = authorized.check_dispatchable(at(500), 0).unwrap_err();
        assert_eq!(denial, Denial::BudgetExceeded);
    }

    #[test]
    fn expiry_is_checked_before_budget() {
        // An expired token with zero budget reports Expired, not BudgetExceeded:
        // the expiry check runs first.
        let authorized = cap(Authority::Mutating)
            .authorize(call(Authority::Mutating, storm_gate()))
            .unwrap();
        let denial = authorized.check_dispatchable(at(2000), 0).unwrap_err();
        assert!(matches!(denial, Denial::Expired { .. }));
    }

    // ── Misc ─────────────────────────────────────────────────────────

    #[test]
    fn hex_is_lowercase_and_64_chars() {
        let hex = ArgsDigest([0x0f; 32]).to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, "0f".repeat(32));
    }

    #[test]
    fn denial_display_strings() {
        assert_eq!(Denial::BudgetExceeded.to_string(), "run dispatch budget exhausted");
        assert_eq!(
            Denial::Expired {
                expiry: at(1000),
                at: at(1001),
            }
            .to_string(),
            "authorization expired"
        );
    }

    #[test]
    fn run_id_and_version_display() {
        assert_eq!(run().to_string(), "run-0001");
        assert_eq!(CapabilityVersion(7).to_string(), "v7");
    }
}
