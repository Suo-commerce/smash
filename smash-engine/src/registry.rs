//! The approved-technique registry — the gate between *declared* and *runnable*.
//!
//! A [`Manifest`](smash_core::fighter::Manifest) only *declares* techniques:
//! handles, required authority, oracle references, prerequisites, evidence
//! schemas. It is inert, handle-only data a decider can hand over. On its own it
//! can introduce **no executable behavior** — there is nothing in a manifest
//! that runs.
//!
//! This registry is what turns a declared handle into something that can run. It
//! maps each [`TechniqueHandle`] (fighter id + technique name) to an *approved*,
//! versioned [`ApprovedTechnique`] implementation that an operator has
//! deliberately registered. A handle with no registered implementation is
//! **unsupported** — not a denial, not a failure of the target, simply not
//! runnable. That is the spec's rule made concrete: "a versioned engine registry
//! maps each handle to an approved implementation; a manifest alone cannot
//! introduce executable behavior."
//!
//! ## The admission cross-check
//!
//! Registration is not just a lookup table. When a manifest is resolved against
//! the registry ([`Registry::resolve_manifest`]), each declared technique is
//! checked against the registered implementation's *own* declaration: the
//! required authority, the oracle reference, the prerequisites, and the evidence
//! schema must agree. The manifest is untrusted handle data (a decider may
//! present it); the implementation is reviewed code. If they disagree — a
//! manifest that claims `ReadOnly` for a technique the code runs as `Mutating`,
//! say — that is an admission failure, not a silently-run probe. Under-declaring
//! the authority a probe needs is exactly the kind of gap this catches.
//!
//! ## What this module is *not* (yet)
//!
//! The registry admits and resolves; it does not execute. [`ApprovedTechnique`]
//! here carries identity, version, and the declared contract. The execution
//! methods (planning the [`Call`](smash_core::capability::Call)s a technique
//! fires, translating wire responses into [`Signal`](smash_core::fighter::Signal)s)
//! extend this trait once the transport and target adapter exist — they need the
//! wire envelope, which is not built yet. Keeping admission separate from
//! execution means the "is this runnable and does it match its declaration?"
//! question is answered before a single byte is on the wire.

use smash_core::fighter::{FighterId, Manifest, Technique, TechniqueName};
use std::collections::BTreeMap;
use std::fmt;

// ── Handle and version ──────────────────────────────────────────────────────

/// The registry key: a fighter id plus a technique name. Technique names are
/// unique per fighter, not globally, so the pair is the identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TechniqueHandle {
    pub fighter: FighterId,
    pub technique: TechniqueName,
}

impl TechniqueHandle {
    pub fn new(fighter: FighterId, technique: TechniqueName) -> Self {
        TechniqueHandle { fighter, technique }
    }
}

impl fmt::Display for TechniqueHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.fighter, self.technique)
    }
}

/// The version of a registered technique *implementation*. Recorded in the
/// evidence bundle so a verdict is scoped to the exact code that produced it.
/// Distinct from the manifest's fighter version: the fighter version describes
/// the declared repertoire, this describes the implementation behind one handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TechniqueVersion(pub u32);

impl fmt::Display for TechniqueVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

// ── The approved implementation contract ────────────────────────────────────

/// An approved technique implementation. The registry holds these; a handle is
/// runnable only if one is registered for it.
///
/// For now the contract is identity + version + the [`Technique`] the
/// implementation claims to satisfy. Execution methods are added as an extension
/// once transport exists (see the module docs) — admission is deliberately
/// answerable without any IO.
pub trait ApprovedTechnique {
    /// The fighter this implementation belongs to.
    fn fighter_id(&self) -> &FighterId;

    /// The technique name within that fighter.
    fn technique_name(&self) -> &TechniqueName;

    /// The implementation version, pinned for replay.
    fn version(&self) -> TechniqueVersion;

    /// The technique contract this implementation claims to satisfy. The
    /// registry cross-checks this against the manifest's declaration at resolve
    /// time; the two must agree, or the handle is rejected as a contract
    /// mismatch rather than run.
    fn declares(&self) -> &Technique;
}

/// A registered entry: an approved implementation plus its cached handle.
pub struct RegisteredTechnique {
    handle: TechniqueHandle,
    implementation: Box<dyn ApprovedTechnique>,
}

impl RegisteredTechnique {
    pub fn handle(&self) -> &TechniqueHandle {
        &self.handle
    }

    pub fn version(&self) -> TechniqueVersion {
        self.implementation.version()
    }

    /// The contract the implementation declares.
    pub fn declares(&self) -> &Technique {
        self.implementation.declares()
    }

    /// The implementation itself, for the executor (once it exists) to drive.
    pub fn implementation(&self) -> &dyn ApprovedTechnique {
        self.implementation.as_ref()
    }
}

impl fmt::Debug for RegisteredTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // dyn ApprovedTechnique is not Debug; show the handle and version.
        f.debug_struct("RegisteredTechnique")
            .field("handle", &self.handle)
            .field("version", &self.version())
            .finish()
    }
}

// ── Errors and admission results ────────────────────────────────────────────

/// Why registration was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryError {
    /// A different implementation is already registered for this handle.
    /// Registration is explicit and non-clobbering; a version change is a new
    /// registry build, not an in-place overwrite.
    AlreadyRegistered { handle: TechniqueHandle },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::AlreadyRegistered { handle } => {
                write!(f, "a technique is already registered for handle {handle}")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

/// Which part of the declared contract disagreed between a manifest and the
/// registered implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContractField {
    RequiredAuthority,
    Oracle,
    Prerequisites,
    EvidenceSchema,
}

impl fmt::Display for ContractField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ContractField::RequiredAuthority => "required authority",
            ContractField::Oracle => "oracle",
            ContractField::Prerequisites => "prerequisites",
            ContractField::EvidenceSchema => "evidence schema",
        };
        f.write_str(s)
    }
}

/// Why a declared technique could not be admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdmissionError {
    /// No approved implementation is registered for this handle — unsupported,
    /// not runnable. A manifest cannot conjure behavior.
    Unregistered { handle: TechniqueHandle },
    /// An implementation exists, but the manifest's declaration disagrees with
    /// the implementation's own on the named field.
    ContractMismatch {
        handle: TechniqueHandle,
        field: ContractField,
    },
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdmissionError::Unregistered { handle } => {
                write!(f, "no approved implementation registered for {handle}")
            }
            AdmissionError::ContractMismatch { handle, field } => {
                write!(
                    f,
                    "manifest and implementation disagree on {field} for {handle}"
                )
            }
        }
    }
}

impl std::error::Error for AdmissionError {}

/// The outcome of resolving a manifest against the registry: which techniques
/// are admitted (registered and contract-matched) and which were rejected.
#[derive(Debug)]
pub struct AdmissionReport<'r> {
    admitted: Vec<&'r RegisteredTechnique>,
    rejected: Vec<AdmissionError>,
}

impl<'r> AdmissionReport<'r> {
    /// The techniques cleared to run.
    pub fn admitted(&self) -> &[&'r RegisteredTechnique] {
        &self.admitted
    }

    /// The techniques that could not be admitted, with reasons.
    pub fn rejected(&self) -> &[AdmissionError] {
        &self.rejected
    }

    /// Whether every declared technique was admitted. A manifest with any
    /// rejection is not fully runnable — the run reports the gap as unsupported
    /// coverage rather than pretending it ran.
    pub fn is_fully_admitted(&self) -> bool {
        self.rejected.is_empty()
    }
}

// ── The registry ────────────────────────────────────────────────────────────

/// The versioned map from handle to approved implementation.
#[derive(Default)]
pub struct Registry {
    map: BTreeMap<TechniqueHandle, RegisteredTechnique>,
}

impl Registry {
    pub fn new() -> Self {
        Registry {
            map: BTreeMap::new(),
        }
    }

    /// Register an approved implementation. Non-clobbering: a handle already
    /// present is an error, never a silent overwrite.
    pub fn register(
        &mut self,
        implementation: Box<dyn ApprovedTechnique>,
    ) -> Result<(), RegistryError> {
        let handle = TechniqueHandle::new(
            implementation.fighter_id().clone(),
            implementation.technique_name().clone(),
        );
        if self.map.contains_key(&handle) {
            return Err(RegistryError::AlreadyRegistered { handle });
        }
        self.map.insert(
            handle.clone(),
            RegisteredTechnique {
                handle,
                implementation,
            },
        );
        Ok(())
    }

    pub fn get(&self, handle: &TechniqueHandle) -> Option<&RegisteredTechnique> {
        self.map.get(handle)
    }

    pub fn contains(&self, handle: &TechniqueHandle) -> bool {
        self.map.contains_key(handle)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Resolve a manifest against the registry. For each declared technique,
    /// confirm an approved implementation exists *and* that the manifest's
    /// declaration agrees with the implementation's. Returns the admitted
    /// techniques and the rejections, collected (not short-circuited) so a
    /// report can show every gap at once.
    pub fn resolve_manifest(&self, manifest: &Manifest) -> AdmissionReport<'_> {
        let mut admitted = Vec::new();
        let mut rejected = Vec::new();

        for declared in manifest.techniques() {
            let handle = TechniqueHandle::new(manifest.id().clone(), declared.name().clone());
            match self.map.get(&handle) {
                None => rejected.push(AdmissionError::Unregistered { handle }),
                Some(entry) => match contract_mismatch(declared, entry.declares()) {
                    Some(field) => {
                        rejected.push(AdmissionError::ContractMismatch { handle, field })
                    }
                    None => admitted.push(entry),
                },
            }
        }

        AdmissionReport { admitted, rejected }
    }
}

/// Compare a manifest's declared technique with an implementation's own
/// declaration. Returns the first field that disagrees, or `None` if they
/// match on everything that governs how the probe runs. The human-readable
/// description and the name are not part of the contract check — the name is
/// the handle, and the description is prose.
fn contract_mismatch(manifest_decl: &Technique, impl_decl: &Technique) -> Option<ContractField> {
    if manifest_decl.required_authority() != impl_decl.required_authority() {
        return Some(ContractField::RequiredAuthority);
    }
    if manifest_decl.oracle() != impl_decl.oracle() {
        return Some(ContractField::Oracle);
    }
    if manifest_decl.prerequisites() != impl_decl.prerequisites() {
        return Some(ContractField::Prerequisites);
    }
    if manifest_decl.evidence_schema() != impl_decl.evidence_schema() {
        return Some(ContractField::EvidenceSchema);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use smash_core::capability::Authority;
    use smash_core::fighter::{
        EvidenceSchema, FighterId, FighterVersion, Manifest, OracleId, OracleKind, OracleRef,
        OracleVersion, Prerequisite, Technique, TechniqueName,
    };

    /// A minimal approved implementation for tests: it just carries a declared
    /// Technique and identity.
    struct TestTechnique {
        fighter: FighterId,
        name: TechniqueName,
        version: TechniqueVersion,
        declared: Technique,
    }

    impl ApprovedTechnique for TestTechnique {
        fn fighter_id(&self) -> &FighterId {
            &self.fighter
        }
        fn technique_name(&self) -> &TechniqueName {
            &self.name
        }
        fn version(&self) -> TechniqueVersion {
            self.version
        }
        fn declares(&self) -> &Technique {
            &self.declared
        }
    }

    fn clamp_technique() -> Technique {
        Technique::new(
            TechniqueName::new("write-via-readonly-session"),
            Authority::Mutating,
            OracleRef::new(
                OracleKind::Differential,
                OracleId::new("authority-clamp-differential-oracle"),
                OracleVersion(1),
            ),
            vec![Prerequisite::CanaryBackend, Prerequisite::StateSnapshot],
            EvidenceSchema::new("differential-pair", 1),
            "attempt a write through a session declared read-only",
        )
    }

    fn clamp_impl(declared: Technique) -> Box<dyn ApprovedTechnique> {
        Box::new(TestTechnique {
            fighter: FighterId::new("authority-clamp-differential"),
            name: TechniqueName::new("write-via-readonly-session"),
            version: TechniqueVersion(1),
            declared,
        })
    }

    fn manifest_with(tech: Technique) -> Manifest {
        Manifest::new(
            FighterId::new("authority-clamp-differential"),
            FighterVersion(1),
            vec![tech],
        )
    }

    // ── Registration ─────────────────────────────────────────────────

    #[test]
    fn register_and_lookup() {
        let mut reg = Registry::new();
        assert!(reg.is_empty());
        reg.register(clamp_impl(clamp_technique())).unwrap();
        assert_eq!(reg.len(), 1);

        let handle = TechniqueHandle::new(
            FighterId::new("authority-clamp-differential"),
            TechniqueName::new("write-via-readonly-session"),
        );
        assert!(reg.contains(&handle));
        let entry = reg.get(&handle).expect("registered");
        assert_eq!(entry.version(), TechniqueVersion(1));
        assert_eq!(entry.handle(), &handle);
    }

    #[test]
    fn duplicate_registration_is_rejected() {
        let mut reg = Registry::new();
        reg.register(clamp_impl(clamp_technique())).unwrap();
        let err = reg.register(clamp_impl(clamp_technique())).unwrap_err();
        match err {
            RegistryError::AlreadyRegistered { handle } => {
                assert_eq!(
                    handle.technique,
                    TechniqueName::new("write-via-readonly-session")
                );
            }
        }
        assert_eq!(reg.len(), 1, "a rejected register must not clobber");
    }

    #[test]
    fn lookup_miss_returns_none() {
        let reg = Registry::new();
        let handle = TechniqueHandle::new(FighterId::new("ghost"), TechniqueName::new("nope"));
        assert!(reg.get(&handle).is_none());
        assert!(!reg.contains(&handle));
    }

    // ── Admission: the manifest-can't-conjure-behavior rule ──────────

    #[test]
    fn unregistered_handle_is_unsupported_not_runnable() {
        // A manifest declaring a technique with no registered implementation
        // is rejected as Unregistered — the manifest alone introduces nothing.
        let reg = Registry::new();
        let report = reg.resolve_manifest(&manifest_with(clamp_technique()));
        assert!(!report.is_fully_admitted());
        assert!(report.admitted().is_empty());
        assert_eq!(report.rejected().len(), 1);
        assert!(matches!(
            report.rejected()[0],
            AdmissionError::Unregistered { .. }
        ));
    }

    #[test]
    fn registered_and_matching_manifest_is_admitted() {
        let mut reg = Registry::new();
        reg.register(clamp_impl(clamp_technique())).unwrap();
        let report = reg.resolve_manifest(&manifest_with(clamp_technique()));
        assert!(report.is_fully_admitted());
        assert_eq!(report.admitted().len(), 1);
        assert!(report.rejected().is_empty());
        assert_eq!(report.admitted()[0].version(), TechniqueVersion(1));
    }

    // ── Admission: the contract cross-check ──────────────────────────

    #[test]
    fn authority_mismatch_is_rejected() {
        // The implementation runs as Mutating; the manifest under-declares it
        // as ReadOnly. That gap must be caught, not run.
        let mut reg = Registry::new();
        reg.register(clamp_impl(clamp_technique())).unwrap();

        let under_declared = Technique::new(
            TechniqueName::new("write-via-readonly-session"),
            Authority::ReadOnly, // impl is Mutating
            OracleRef::new(
                OracleKind::Differential,
                OracleId::new("authority-clamp-differential-oracle"),
                OracleVersion(1),
            ),
            vec![Prerequisite::CanaryBackend, Prerequisite::StateSnapshot],
            EvidenceSchema::new("differential-pair", 1),
            "attempt a write through a session declared read-only",
        );
        let report = reg.resolve_manifest(&manifest_with(under_declared));
        assert!(!report.is_fully_admitted());
        assert_eq!(
            report.rejected()[0],
            AdmissionError::ContractMismatch {
                handle: TechniqueHandle::new(
                    FighterId::new("authority-clamp-differential"),
                    TechniqueName::new("write-via-readonly-session"),
                ),
                field: ContractField::RequiredAuthority,
            }
        );
    }

    #[test]
    fn oracle_version_mismatch_is_rejected() {
        let mut reg = Registry::new();
        reg.register(clamp_impl(clamp_technique())).unwrap();

        let wrong_oracle = Technique::new(
            TechniqueName::new("write-via-readonly-session"),
            Authority::Mutating,
            OracleRef::new(
                OracleKind::Differential,
                OracleId::new("authority-clamp-differential-oracle"),
                OracleVersion(2), // impl pins v1
            ),
            vec![Prerequisite::CanaryBackend, Prerequisite::StateSnapshot],
            EvidenceSchema::new("differential-pair", 1),
            "attempt a write through a session declared read-only",
        );
        let report = reg.resolve_manifest(&manifest_with(wrong_oracle));
        assert_eq!(
            report.rejected()[0],
            AdmissionError::ContractMismatch {
                handle: TechniqueHandle::new(
                    FighterId::new("authority-clamp-differential"),
                    TechniqueName::new("write-via-readonly-session"),
                ),
                field: ContractField::Oracle,
            }
        );
    }

    #[test]
    fn prerequisites_mismatch_is_rejected() {
        let mut reg = Registry::new();
        reg.register(clamp_impl(clamp_technique())).unwrap();

        let fewer_prereqs = Technique::new(
            TechniqueName::new("write-via-readonly-session"),
            Authority::Mutating,
            OracleRef::new(
                OracleKind::Differential,
                OracleId::new("authority-clamp-differential-oracle"),
                OracleVersion(1),
            ),
            vec![Prerequisite::CanaryBackend], // impl also needs StateSnapshot
            EvidenceSchema::new("differential-pair", 1),
            "attempt a write through a session declared read-only",
        );
        let report = reg.resolve_manifest(&manifest_with(fewer_prereqs));
        assert_eq!(
            report.rejected()[0],
            AdmissionError::ContractMismatch {
                handle: TechniqueHandle::new(
                    FighterId::new("authority-clamp-differential"),
                    TechniqueName::new("write-via-readonly-session"),
                ),
                field: ContractField::Prerequisites,
            }
        );
    }

    #[test]
    fn evidence_schema_mismatch_is_rejected() {
        let mut reg = Registry::new();
        reg.register(clamp_impl(clamp_technique())).unwrap();

        let wrong_schema = Technique::new(
            TechniqueName::new("write-via-readonly-session"),
            Authority::Mutating,
            OracleRef::new(
                OracleKind::Differential,
                OracleId::new("authority-clamp-differential-oracle"),
                OracleVersion(1),
            ),
            vec![Prerequisite::CanaryBackend, Prerequisite::StateSnapshot],
            EvidenceSchema::new("differential-pair", 2), // impl pins v1
            "attempt a write through a session declared read-only",
        );
        let report = reg.resolve_manifest(&manifest_with(wrong_schema));
        assert_eq!(
            report.rejected()[0],
            AdmissionError::ContractMismatch {
                handle: TechniqueHandle::new(
                    FighterId::new("authority-clamp-differential"),
                    TechniqueName::new("write-via-readonly-session"),
                ),
                field: ContractField::EvidenceSchema,
            }
        );
    }

    // ── Mixed report collects every gap ──────────────────────────────

    #[test]
    fn report_collects_all_gaps_not_just_the_first() {
        let mut reg = Registry::new();
        reg.register(clamp_impl(clamp_technique())).unwrap();

        // Manifest declares two techniques: one matches, one is unregistered.
        let extra = Technique::new(
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
        );
        let manifest = Manifest::new(
            FighterId::new("authority-clamp-differential"),
            FighterVersion(1),
            vec![clamp_technique(), extra],
        );
        let report = reg.resolve_manifest(&manifest);
        assert_eq!(report.admitted().len(), 1);
        assert_eq!(report.rejected().len(), 1);
        assert!(matches!(
            report.rejected()[0],
            AdmissionError::Unregistered { .. }
        ));
    }

    // ── Display ──────────────────────────────────────────────────────

    #[test]
    fn handle_and_version_display() {
        let h = TechniqueHandle::new(
            FighterId::new("authority-clamp-differential"),
            TechniqueName::new("write-via-readonly-session"),
        );
        assert_eq!(
            h.to_string(),
            "authority-clamp-differential/write-via-readonly-session"
        );
        assert_eq!(TechniqueVersion(3).to_string(), "v3");
    }

    #[test]
    fn contract_field_display() {
        assert_eq!(
            ContractField::RequiredAuthority.to_string(),
            "required authority"
        );
        assert_eq!(ContractField::EvidenceSchema.to_string(), "evidence schema");
    }
}
