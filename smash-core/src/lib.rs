//! # smash-core
//!
//! The executor-referee keystone for Smash. Everything downstream has to stay
//! honest to the types declared here, so this crate holds only what must be
//! true before any probe is safe to fire — and nothing that speaks a wire
//! format.
//!
//! ## Containment by construction
//!
//! The central invariant is that Smash cannot emit a probe outside the match's
//! scope or above its authority ceiling. This is enforced by the type system,
//! not by discipline: a raw [`capability::Call`] is inert data, and the only
//! way to obtain a [`capability::AuthorizedCall`] (the only thing the engine
//! will dispatch) is to pass a `Call` through [`capability::Capability::authorize`].
//! `AuthorizedCall` has a private field and no other constructor — not `Default`,
//! not `Deserialize`, not a public tuple literal — so an off-stage instance is
//! unrepresentable.
//!
//! ## Two axes, kept separate
//!
//! [`capability::Authority`] is deliberately two-valued (`ReadOnly < Mutating`):
//! it models what *Smash* may attempt, not how the *target* classifies an
//! effect. A target's severity classification (e.g. Storm Gate's
//! `write:taint_exempt`) lives on a separate axis that core does not model at
//! all — it is target-read metadata a fighter consults. Keeping the authority
//! ceiling free of severity is what lets a future taint-exemption fighter probe
//! *on* the severity axis rather than having it baked into the ceiling.
//!
//! ## Key alignment
//!
//! [`capability::Call::key`] emits `power_move:<tool>:<hex(sha256(args))>`, the
//! same canonical form the target gate signs its vouch with. Canonicalization
//! of the arguments is deliberately *not* done here — it lives upstream in
//! `smash-engine`, which speaks the wire envelope. That keeps core dep-free,
//! but it moves the byte-identity risk upstream too: the engine's canonicalizer
//! is the single point that must match the target's, and that match is pinned
//! by a cross-implementation test vector in `smash-engine`, not here.

pub mod capability;
pub mod correlation;
pub mod execution;
pub mod fighter;
pub mod lifecycle;
pub mod research;
pub mod verdict;
