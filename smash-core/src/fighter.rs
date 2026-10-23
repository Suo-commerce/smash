//! Fighter types: the handle-only manifest and abstract observation contract.
//!
//! A fighter is a pluggable adversarial pack that probes a target for a class
//! of vulnerability. This module defines what a fighter *declares* about itself
//! (the [`Manifest`]) and what it *produces* ([`Observation`]s), without ever
//! exposing adversarial payload content.
//!
//! ## Containment: handles only
//!
//! The manifest is what a harness or decider sees when choosing which fighters
//! to field. It contains **handles** — technique names, required authority
//! levels, oracle identifiers, prerequisites, evidence schemas — never payload
//! strings, adversarial prompts, or wire-format data. A harness that receives a
//! `Manifest` can reason about fighters without adversarial content entering
//! its context. This is the other half of containment by construction:
//! [`capability`] stops Smash from going off-stage; the manifest stops the
//! stage from leaking into the audience.
//!
//! Every handle in the manifest is a *typed* value, not free text the decider
//! supplies. The decider selects registered handles and narrowly typed
//! parameters; it cannot submit arbitrary URLs, payloads, free-form request
//! bodies, or an authority declaration that overrides the registered technique.
//!
//! The same principle holds for observations: a [`Signal`] carries structured
//! facts (accepted/rejected, timing) rather than raw response bodies. The
//! engine translates wire responses into signals; the fighter and oracle work
//! only with the abstraction.
//!
//! ## Versioning and replay
//!
//! A manifest carries a [`FighterVersion`], and each [`Technique`] pins an
//! [`OracleRef`] (kind + identifier + version) and an [`EvidenceSchema`]. These
//! are what make a verdict *replayable*: `smash verify` recomputes the verdict
//! with the pinned oracle against evidence in the recorded schema, and rejects
//! an unsupported version rather than inventing a pass. A manifest alone cannot
//! introduce executable behavior — a versioned engine registry maps each handle
//! to an approved implementation.
//!
//! ## Trait shape
//!
//! The [`Fighter`] trait in core is intentionally minimal: just
//! [`manifest()`](Fighter::manifest). Execution — firing probes, reading wire
//! responses, translating them into [`Signal`]s — is the engine's job.
//! Core defines the contract (what a fighter IS), not the IO (what it DOES
//! on the wire). The engine extends this with execution methods that have
//! access to the wire envelope.
//!
//! [`capability`]: crate::capability

use crate::capability::{Authority, CallKey};
use std::fmt;

// ── Identity and versioning ─────────────────────────────────────────────────

/// A fighter's stable identifier. Used in manifests, match logs, and the
/// replay contract. Convention: kebab-case, e.g. `"authority-clamp-differential"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FighterId(String);

impl FighterId {
    pub fn new(id: impl Into<String>) -> Self {
        FighterId(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FighterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A fighter manifest's version. Bumped whenever the repertoire or the meaning
/// of any technique changes, so a recorded verdict is scoped to the exact
/// fighter that produced it. The evidence bundle records this version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FighterVersion(pub u32);

impl fmt::Display for FighterVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// A technique's name within a fighter. Unique per fighter, not globally.
/// Convention: kebab-case, e.g. `"write-via-readonly-session"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TechniqueName(String);

impl TechniqueName {
    pub fn new(name: impl Into<String>) -> Self {
        TechniqueName(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TechniqueName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── Oracle classification and identity ──────────────────────────────────────

/// How the oracle evaluates a technique's results. Declared up front so the
/// engine knows what to provision (e.g. a canary backend for differential
/// techniques). The oracle itself lives in the engine; this is the selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OracleKind {
    /// Expected outcome is fully determined before the probe fires.
    /// Pass/fail against a known-good answer.
    Deterministic,

    /// Fire a probe *and* a benign control through the same path; compare.
    /// Requires a canary observable — the engine provisions one. Chokepoint
    /// kills (e.g. Storm Gate authority clamping) are mostly this.
    Differential,

    /// Measure timing, resource consumption, or behavioral side channels.
    /// The oracle applies a statistical threshold.
    Behavioral,
}

impl fmt::Display for OracleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OracleKind::Deterministic => f.write_str("deterministic"),
            OracleKind::Differential => f.write_str("differential"),
            OracleKind::Behavioral => f.write_str("behavioral"),
        }
    }
}

/// The identifier of a specific oracle implementation. Convention: kebab-case,
/// e.g. `"authority-clamp-differential-oracle"`. Together with an
/// [`OracleVersion`] this pins *which* evaluator a verdict was computed with, so
/// offline verification can recompute with the same one — or fail cleanly if it
/// is unavailable.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OracleId(String);

impl OracleId {
    pub fn new(id: impl Into<String>) -> Self {
        OracleId(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OracleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The pinned version of an oracle implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OracleVersion(pub u32);

impl fmt::Display for OracleVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// A full reference to the oracle a technique is evaluated by: its *kind*
/// (what the engine must provision), its *identifier* (which implementation),
/// and its *version* (pinned for replay).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleRef {
    kind: OracleKind,
    id: OracleId,
    version: OracleVersion,
}

impl OracleRef {
    pub fn new(kind: OracleKind, id: OracleId, version: OracleVersion) -> Self {
        OracleRef { kind, id, version }
    }

    pub fn kind(&self) -> OracleKind {
        self.kind
    }

    pub fn id(&self) -> &OracleId {
        &self.id
    }

    pub fn version(&self) -> OracleVersion {
        self.version
    }
}

impl fmt::Display for OracleRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({} {})", self.id, self.kind, self.version)
    }
}

// ── Prerequisites ───────────────────────────────────────────────────────────

/// A precondition the engine must satisfy before a technique can run. These are
/// typed handles, not free text: the engine knows how to provision each one in
/// an isolated fixture, and a technique that names an unsupported prerequisite
/// is rejected at registration rather than improvised at runtime.
///
/// Forward-compatible: new variants may be added. Match arms must include a
/// wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Prerequisite {
    /// A disposable canary backend with an observable write receipt. Required
    /// by differential techniques that need to detect a real backend effect.
    CanaryBackend,
    /// An authoritative before/after snapshot of protected state, so an effect
    /// can be correlated rather than inferred from a response.
    StateSnapshot,
    /// A unique, isolated run namespace, so concurrent or repeated runs cannot
    /// borrow one another's effects.
    IsolatedNamespace,
    /// A session established at the given authority — e.g. a write-enabled
    /// control session used as the benign half of a differential pair.
    Session { authority: Authority },
}

impl fmt::Display for Prerequisite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Prerequisite::CanaryBackend => f.write_str("canary-backend"),
            Prerequisite::StateSnapshot => f.write_str("state-snapshot"),
            Prerequisite::IsolatedNamespace => f.write_str("isolated-namespace"),
            Prerequisite::Session { authority } => write!(f, "session({authority})"),
        }
    }
}

// ── Evidence schema ─────────────────────────────────────────────────────────

/// The schema of the evidence a technique produces. The oracle reads evidence
/// in this schema, and offline verification checks that the stored evidence
/// matches a schema/version it supports — an unsupported schema is a
/// verification failure, never a silent pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceSchema {
    id: String,
    version: u32,
}

impl EvidenceSchema {
    pub fn new(id: impl Into<String>, version: u32) -> Self {
        EvidenceSchema {
            id: id.into(),
            version,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn version(&self) -> u32 {
        self.version
    }
}

impl fmt::Display for EvidenceSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@v{}", self.id, self.version)
    }
}

// ── Manifest ──────────────────────────────────────────────────────────────

/// One technique in a fighter's repertoire. A handle, not a payload.
///
/// This is what a decider/harness sees when choosing plays. It carries enough
/// to decide "should I field this technique in this match?" — the authority it
/// needs, the oracle that will judge it, what the engine must provision, and
/// the shape of the evidence it will produce — without seeing the actual
/// adversarial content the technique will emit.
#[derive(Debug, Clone)]
pub struct Technique {
    name: TechniqueName,
    required_authority: Authority,
    oracle: OracleRef,
    prerequisites: Vec<Prerequisite>,
    evidence_schema: EvidenceSchema,
    /// Human-readable summary of what this technique probes. Written by the
    /// fighter author — a sentence like "attempt a write through a session
    /// declared read-only". Not generated from payload content.
    description: String,
}

impl Technique {
    pub fn new(
        name: TechniqueName,
        required_authority: Authority,
        oracle: OracleRef,
        prerequisites: Vec<Prerequisite>,
        evidence_schema: EvidenceSchema,
        description: impl Into<String>,
    ) -> Self {
        Technique {
            name,
            required_authority,
            oracle,
            prerequisites,
            evidence_schema,
            description: description.into(),
        }
    }

    pub fn name(&self) -> &TechniqueName {
        &self.name
    }

    /// The authority this technique requires — its bound *effect requirement*,
    /// based on what the probe may do if the target is vulnerable.
    pub fn required_authority(&self) -> Authority {
        self.required_authority
    }

    /// The full oracle reference (kind + identifier + version).
    pub fn oracle(&self) -> &OracleRef {
        &self.oracle
    }

    /// Convenience accessor for the oracle *kind* — what the engine provisions.
    pub fn oracle_kind(&self) -> OracleKind {
        self.oracle.kind()
    }

    /// What the engine must provision before this technique can run.
    pub fn prerequisites(&self) -> &[Prerequisite] {
        &self.prerequisites
    }

    /// The schema of the evidence this technique produces.
    pub fn evidence_schema(&self) -> &EvidenceSchema {
        &self.evidence_schema
    }

    pub fn description(&self) -> &str {
        &self.description
    }
}

/// A fighter's complete manifest — handles only.
///
/// The decider sees this when deciding what to play. The engine sees it when
/// setting up oracles (e.g. provisioning a canary for differential techniques)
/// and satisfying prerequisites. Neither sees payload content.
#[derive(Debug, Clone)]
pub struct Manifest {
    id: FighterId,
    version: FighterVersion,
    techniques: Vec<Technique>,
}

impl Manifest {
    pub fn new(id: FighterId, version: FighterVersion, techniques: Vec<Technique>) -> Self {
        Manifest {
            id,
            version,
            techniques,
        }
    }

    pub fn id(&self) -> &FighterId {
        &self.id
    }

    /// The manifest version — recorded with every verdict for replay scoping.
    pub fn version(&self) -> FighterVersion {
        self.version
    }

    pub fn techniques(&self) -> &[Technique] {
        &self.techniques
    }

    /// Look up a technique by name. Returns `None` if this fighter doesn't
    /// have it — the engine treats that as a bug in the decider, not a denial.
    pub fn technique(&self, name: &TechniqueName) -> Option<&Technique> {
        self.techniques.iter().find(|t| &t.name == name)
    }
}

// ── Signals and observations ──────────────────────────────────────────────

/// What the engine observed when a probe fired. Abstract — no raw response
/// bodies, no wire bytes. The engine translates HTTP responses / gate verdicts
/// into these before the oracle sees them.
///
/// Forward-compatible: new variants may be added. A fighter or oracle that
/// encounters an unknown signal should skip it, not panic.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Signal {
    /// The target gate accepted or rejected the call.
    GateVerdict {
        /// `true` if the call passed through the gate and reached the backend.
        accepted: bool,
    },

    /// Two calls fired through the same path: a probe and a benign control.
    /// The oracle compares them. This is the bread and butter of chokepoint
    /// kills: if the probe was accepted but should have been rejected (or
    /// vice versa relative to the control), something is wrong.
    DifferentialPair {
        probe_accepted: bool,
        control_accepted: bool,
    },

    /// A timing measurement in microseconds. The control is present for
    /// differential timing attacks; absent for absolute threshold checks.
    Timing {
        probe_us: u64,
        control_us: Option<u64>,
    },
}

/// One observation: a technique applied via a specific call, producing a
/// signal. This is what the match log records and the oracle judges.
///
/// The [`CallKey`] ties the observation to the exact authorized call that
/// produced it — same key the target gate signs its vouch with — enabling
/// replay: `smash verify <run-id>` can match each observation back to the
/// call that created it.
#[derive(Debug, Clone)]
pub struct Observation {
    technique: TechniqueName,
    call_key: CallKey,
    signal: Signal,
}

impl Observation {
    pub fn new(technique: TechniqueName, call_key: CallKey, signal: Signal) -> Self {
        Observation {
            technique,
            call_key,
            signal,
        }
    }

    pub fn technique(&self) -> &TechniqueName {
        &self.technique
    }

    pub fn call_key(&self) -> &CallKey {
        &self.call_key
    }

    pub fn signal(&self) -> &Signal {
        &self.signal
    }
}

// ── Trait ──────────────────────────────────────────────────────────────────

/// The core fighter contract. Implementations live in fighter-pack crates or
/// in the engine, not in core — core defines the shape.
///
/// The trait is intentionally minimal: just the manifest. Execution — building
/// [`Call`](crate::capability::Call)s, firing them, translating wire responses
/// into [`Signal`]s — is the engine's responsibility. The engine may define an
/// extended execution trait that adds async IO methods; that trait is not
/// core's concern.
///
/// Why so thin? A `Call` needs an [`ArgsDigest`](crate::capability::ArgsDigest),
/// which requires canonical-JSON hashing. That lives in the engine (which
/// speaks the wire envelope), not here (which is std-only and dep-free).
/// Putting probe-planning in this trait would force core to depend on a JSON
/// library, breaking the keystone's zero-dep invariant.
pub trait Fighter {
    /// The handle-only manifest. Cached at registration time; must be stable
    /// for the fighter's lifetime.
    fn manifest(&self) -> &Manifest;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clamp_fighter() -> Manifest {
        Manifest::new(
            FighterId::new("authority-clamp-differential"),
            FighterVersion(1),
            vec![
                Technique::new(
                    TechniqueName::new("write-via-readonly-session"),
                    Authority::Mutating,
                    OracleRef::new(
                        OracleKind::Differential,
                        OracleId::new("authority-clamp-differential-oracle"),
                        OracleVersion(1),
                    ),
                    vec![
                        Prerequisite::CanaryBackend,
                        Prerequisite::StateSnapshot,
                        Prerequisite::IsolatedNamespace,
                        Prerequisite::Session {
                            authority: Authority::Mutating,
                        },
                    ],
                    EvidenceSchema::new("differential-pair", 1),
                    "attempt a write through a session declared read-only",
                ),
                Technique::new(
                    TechniqueName::new("read-sanity-check"),
                    Authority::ReadOnly,
                    OracleRef::new(
                        OracleKind::Deterministic,
                        OracleId::new("read-sanity-oracle"),
                        OracleVersion(1),
                    ),
                    vec![],
                    EvidenceSchema::new("gate-verdict", 1),
                    "confirm that a read through a read-only session succeeds",
                ),
            ],
        )
    }

    #[test]
    fn manifest_carries_version() {
        let m = clamp_fighter();
        assert_eq!(m.version(), FighterVersion(1));
        assert_eq!(m.version().to_string(), "v1");
    }

    #[test]
    fn manifest_lookup_by_name() {
        let m = clamp_fighter();
        let name = TechniqueName::new("write-via-readonly-session");
        let tech = m.technique(&name).expect("technique should exist");
        assert_eq!(tech.required_authority(), Authority::Mutating);
        assert_eq!(tech.oracle_kind(), OracleKind::Differential);
    }

    #[test]
    fn manifest_lookup_miss_returns_none() {
        let m = clamp_fighter();
        let ghost = TechniqueName::new("does-not-exist");
        assert!(m.technique(&ghost).is_none());
    }

    #[test]
    fn technique_preserves_description() {
        let m = clamp_fighter();
        let name = TechniqueName::new("read-sanity-check");
        let tech = m.technique(&name).unwrap();
        assert_eq!(
            tech.description(),
            "confirm that a read through a read-only session succeeds"
        );
    }

    #[test]
    fn technique_pins_oracle_identity_and_version() {
        let m = clamp_fighter();
        let tech = m
            .technique(&TechniqueName::new("write-via-readonly-session"))
            .unwrap();
        let oracle = tech.oracle();
        assert_eq!(oracle.kind(), OracleKind::Differential);
        assert_eq!(
            oracle.id(),
            &OracleId::new("authority-clamp-differential-oracle")
        );
        assert_eq!(oracle.version(), OracleVersion(1));
    }

    #[test]
    fn technique_declares_prerequisites() {
        let m = clamp_fighter();
        let tech = m
            .technique(&TechniqueName::new("write-via-readonly-session"))
            .unwrap();
        let prereqs = tech.prerequisites();
        assert!(prereqs.contains(&Prerequisite::CanaryBackend));
        assert!(prereqs.contains(&Prerequisite::StateSnapshot));
        assert!(prereqs.contains(&Prerequisite::IsolatedNamespace));
        assert!(prereqs.contains(&Prerequisite::Session {
            authority: Authority::Mutating,
        }));
    }

    #[test]
    fn read_only_technique_needs_no_prerequisites() {
        let m = clamp_fighter();
        let tech = m
            .technique(&TechniqueName::new("read-sanity-check"))
            .unwrap();
        assert!(tech.prerequisites().is_empty());
    }

    #[test]
    fn technique_carries_evidence_schema() {
        let m = clamp_fighter();
        let tech = m
            .technique(&TechniqueName::new("write-via-readonly-session"))
            .unwrap();
        let schema = tech.evidence_schema();
        assert_eq!(schema.id(), "differential-pair");
        assert_eq!(schema.version(), 1);
        assert_eq!(schema.to_string(), "differential-pair@v1");
    }

    #[test]
    fn observation_binds_technique_to_call_key() {
        use crate::capability::ArgsDigest;

        let technique = TechniqueName::new("write-via-readonly-session");
        // Construct a CallKey the same way capability.rs does.
        let key = crate::capability::Call {
            session: "s-1".into(),
            tool: "memory_write".into(),
            args_digest: ArgsDigest([0xab; 32]),
            required: Authority::Mutating,
            target: crate::capability::Target::new("http://127.0.0.1:8019"),
        }
        .key();

        let obs = Observation::new(
            technique.clone(),
            key.clone(),
            Signal::GateVerdict { accepted: true },
        );

        assert_eq!(obs.technique(), &technique);
        assert_eq!(obs.call_key(), &key);
        assert_eq!(obs.signal(), &Signal::GateVerdict { accepted: true });
    }

    #[test]
    fn differential_pair_distinguishes_probe_and_control() {
        let signal = Signal::DifferentialPair {
            probe_accepted: true,
            control_accepted: false,
        };
        // A probe accepted + control rejected means the gate behaved
        // differently — exactly what the authority-clamp differential
        // fighter is looking for.
        assert_ne!(
            signal,
            Signal::DifferentialPair {
                probe_accepted: false,
                control_accepted: false,
            }
        );
    }

    #[test]
    fn fighter_id_and_technique_name_display() {
        let id = FighterId::new("authority-clamp-differential");
        assert_eq!(id.to_string(), "authority-clamp-differential");

        let name = TechniqueName::new("write-via-readonly-session");
        assert_eq!(name.to_string(), "write-via-readonly-session");
    }

    #[test]
    fn oracle_kind_display() {
        assert_eq!(OracleKind::Deterministic.to_string(), "deterministic");
        assert_eq!(OracleKind::Differential.to_string(), "differential");
        assert_eq!(OracleKind::Behavioral.to_string(), "behavioral");
    }

    #[test]
    fn oracle_ref_display() {
        let oracle = OracleRef::new(
            OracleKind::Differential,
            OracleId::new("authority-clamp-differential-oracle"),
            OracleVersion(2),
        );
        assert_eq!(
            oracle.to_string(),
            "authority-clamp-differential-oracle (differential v2)"
        );
    }

    #[test]
    fn prerequisite_display() {
        assert_eq!(Prerequisite::CanaryBackend.to_string(), "canary-backend");
        assert_eq!(
            Prerequisite::Session {
                authority: Authority::ReadOnly
            }
            .to_string(),
            "session(read-only)"
        );
    }
}
