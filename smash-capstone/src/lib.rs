//! # smash-capstone — concrete differential-discovery wiring + the L0 capstone
//!
//! The safety kernel [`smash_loop`] defines the discovery loop and its ports as
//! *abstractions*; this crate holds the *concrete* port impls and the end-to-end
//! demonstration, so the kernel stays free of target-flavoured code (the design decision
//! of 2026-10-30).
//!
//! - [`harness`] — the real [`Generator`](smash_loop::ports::Generator) /
//!   [`Dispatcher`](smash_loop::ports::Dispatcher) / [`Oracle`](smash_loop::ports::Oracle)
//!   that drive `smash_generator`'s metamorphic pairs through an in-process gate
//!   differential (`smash_engine::differential`), bridging the loop's per-entry ports to
//!   the pair-based oracle via a shared pair-book.
//! - The **L0 capstone** (P3 §10) lives here as an integration test: `DiscoveryRun` over
//!   the harness against a vulnerable gate surfaces the F-B/W1 laundering class, the
//!   findings cluster via `smash_findings`, each re-verifies offline, and flips to Pass on
//!   the fixed gate.
//!
//! This crate depends on loop + generator + engine (and, for the capstone test,
//! `smash-findings`); it is where "the whole thing runs," the application layer the spec
//! calls `smash-loop`/**cli** (§8).

pub mod harness;
pub mod http_fixture;
