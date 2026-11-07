//! # smash-generator — phase-2 model-free candidate generator (quarantined)
//!
//! Build-order phase 2 of `specs/generator-boundary.md` / `generator-model-free.md`.
//! This crate proposes **candidate** probes; it never dispatches, never scores,
//! never widens scope. That guarantee is a **dependency fact**, not a convention:
//! `smash-generator` depends on `smash-core` only. It does not depend on
//! `smash-engine`, so it cannot name `transport`, a `Sender`, or the execute path —
//! there is no code it could write here that reaches the wire. The
//! [`candidate::Candidate`] it emits is inert data; admission (in `smash-loop`) and
//! the capability gate (in `smash-core`/`smash-engine`) are the only paths from a
//! candidate to a dispatch.
//!
//! Unit 1 (here): the declarative candidate format and its canonical key. The
//! mutator library and the search modes (metamorphic pairs, parameter mutation,
//! combinatorial parameterization) are later units that compose these types.
//!
//! ## Why no serde here
//! Params are a core-only [`candidate::ParamValue`] rather than `serde_json::Value`,
//! so this crate's entire dependency surface is `smash-core`. The conversion to the
//! wire's JSON is a loop/engine adapter concern, kept out of the quarantined crate.

pub mod candidate;
pub mod mutators;
pub mod search;
