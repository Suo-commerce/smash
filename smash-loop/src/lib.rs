//! # smash-loop — phase-3 autonomous discovery loop, safety kernel
//!
//! Build-order item 1 of `specs/autonomous-loop.md` (rev 5), **reconciled onto
//! `smash-core`**. The kernel no longer carries shims for identity, verdicts, or
//! lifecycle — those are core's, and the loop builds on them:
//!
//! - execution identity + receipt correlation → `smash_core::correlation::CorrelationKey`
//!   (core already enforces N5/M3: a receipt matching only on call key is rejected);
//! - verdict vocabulary → `smash_core::verdict::Verdict` (five states), with a
//!   loop-side [`verdict::InconclusiveReason`] so a *target-induced timeout* is
//!   distinguishable from a *broken control* (decision: typed reason, not string-parsing);
//! - run/attempt lifecycle + cleanup → `smash_core::lifecycle`
//!   (`RunState`, `AttemptState::Unresolved` triggers the quiescence barrier).
//!
//! What stays loop-side, because it is a discovery-loop concept core does not and
//! should not carry: the region partition and `adequacy_target` ([`RegionId`],
//! decision: engine/loop registry keyed by technique handle), the deterministic
//! **logical epoch** for replay ([`epoch`]), the dispatch ceiling + baseline
//! withholding + feasibility preflight ([`ceiling`]), the two-axis coverage model
//! ([`coverage`]), the quiescence barrier ([`quiescence`]), the within-run
//! dedup/reservation table ([`dedup`]), the admission + dedup lifecycle
//! ([`admission`]), the adaptive steering math ([`steering`]), the run-scoped outcome
//! accumulator ([`accumulator`]), the resolution lockstep ([`run`]), the
//! `TypedFeedback` wall ([`feedback`]), the non-gating exit rule ([`stop`]), the ports
//! ([`ports`]), the parameter-bounds value check ([`param_check`]), and the controller
//! ([`controller`]). The concrete differential-discovery port impls (a generator +
//! dispatcher that drive metamorphic pairs through an in-process gate) live in the
//! application crate `smash-capstone`, not in this kernel.

pub mod accumulator;
pub mod admission;
pub mod ceiling;
pub mod controller;
pub mod coverage;
pub mod dedup;
pub mod driver;
pub mod epoch;
pub mod feedback;
pub mod metamorphic;
pub mod param_check;
pub mod plan;
pub mod ports;
pub mod quiescence;
pub mod regions;
pub mod run;
pub mod steering;
pub mod stop;
pub mod verdict;

/// A canonical candidate key: `f(declarative candidate content)` only — epoch- and
/// run-independent (P3 §0.2). Dedupe and poison bind to this. Distinct from
/// `smash_core::capability::CallKey`, which identifies one concrete wire call: a
/// candidate (template + params + target + oracle binding) may expand to one or
/// more calls, so the candidate key is its own loop-side handle. The engine mints
/// it; opaque here.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct CanonicalKey(pub String);

/// A region handle: one cell of a template's **declared, enumerated** partition
/// (P3 §0.2). Regions live in the engine/loop registry keyed by technique handle
/// (`smash_core::fighter::{FighterId, TechniqueName}`), not in core. Opaque here.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct RegionId(pub String);

// Note: the run identifier is `smash_core::capability::RunId` — the kernel no
// longer defines its own. The deterministic replay tag is `epoch::LogicalEpoch`.
