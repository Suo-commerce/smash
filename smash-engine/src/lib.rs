//! # smash-engine
//!
//! The execution layer. Where [`smash_core`] declares what must be true before
//! a probe is safe to fire, the engine is what actually fires it — and it is
//! the first crate in the workspace allowed to speak a wire format or carry a
//! third-party dependency. That division is deliberate: the keystone stays
//! dependency-free and audit-small, and everything that touches the network,
//! serializes bytes, or orchestrates fixtures lives here, behind the typed
//! contracts core defines.
//!
//! ## Responsibilities (per spec §4)
//!
//! - **Canonicalization** (`canonical`) — the byte-exact JSON encoding of call
//!   arguments and the [`CallKey`](smash_core::capability::CallKey)
//!   construction. This is the highest-stakes code in the crate: its output
//!   must match, byte for byte, the key the target gate (Storm Gate) signs its
//!   vouch with, or the replay contract breaks silently. It is hand-rolled, not
//!   delegated, and pinned by cross-implementation test vectors against the
//!   actual Storm Gate implementation.
//! - **Candidate key** (`candidate_key`) — the internal, content-only candidate
//!   identity for dedup/poison (admission-funnel §2). Distinct from the
//!   target-mirroring `CallKey` above: it is matched against nothing external, so
//!   it reuses `canonical`'s JSON form as a convenience, not as a contract. Admission
//!   recomputes it from validated content rather than trusting an untrusted
//!   generator's supplied key.
//! - **Registry** — maps each manifest handle to an approved, versioned
//!   technique implementation. A [`Manifest`](smash_core::fighter::Manifest)
//!   only *declares*; the registry is the gate between declared and runnable, so
//!   a manifest alone can never introduce executable behavior.
//! - **Parameter bounds** (`bounds`) — the reviewed, versioned per-template param
//!   bounds (`ParamSpec`) owned by the registry; the trusted declaration side of the
//!   §4 stage-2 admission check. The value check lives in `smash-loop`.
//! - **Target adapter** — translates between core's abstract
//!   [`Call`](smash_core::capability::Call) / [`Signal`](smash_core::fighter::Signal)
//!   and the target's wire envelope (OpenAI-compatible JSON for the first
//!   target).
//! - **Transport** — the single controlled egress path every dispatch must go
//!   through: origin validation, destination binding, response-byte limits. TLS
//!   verification is never disabled. The generic M3 fixture pack additionally
//!   disables ambient proxy use and filters its actual connection addresses.

//! - **Fixture orchestration** — provisioning the canary backend, isolated
//!   namespace, and state snapshots a technique's
//!   [`Prerequisite`](smash_core::fighter::Prerequisite)s demand; cleanup on
//!   both success and failure.
//! - **Execution state machine** — drives a run through the
//!   [`lifecycle`](smash_core::lifecycle) states, reserves budget, applies the
//!   dispatch gate
//!   ([`check_dispatchable`](smash_core::capability::AuthorizedCall::check_dispatchable)),
//!   records each attempt with its
//!   [`CorrelationKey`](smash_core::correlation::CorrelationKey), and hands
//!   observations to the oracle. The replayable match log it emits is consumed
//!   downstream by `smash-oracle` and `smash-cli`.
//!
//! ## Containment still holds here
//!
//! The engine sees payload content — it has to, to put bytes on the wire — but
//! it never lets that content back into a decider-facing surface. The manifest
//! wall from core is upheld at every engine boundary: errors, progress events,
//! and summaries carry handles, not adversarial strings. Core makes the wall
//! *representable*; the engine is responsible for *not climbing over it*.
//!
//! Modules are added one at a time as they are built; `canonical` is first.

pub mod adapter;
pub mod bounds;
pub mod candidate_key;
pub mod canonical;
pub mod differential;
pub mod execute;
pub mod http;
pub mod http_sender;
pub mod matchlog;
pub mod recon;
pub mod registry;
pub mod repro;
pub mod transport;
pub mod workflow;
