//! Item 2 — the region partition + `adequacy_target` registry, and candidate
//! admission: parameter bounds (stage 2), region-assignability (M7) and oracle-binding
//! (N7).
//!
//! Decision (crate layering): regions are keyed by the engine's
//! [`TechniqueHandle`] and the loop reads the engine [`Registry`] for the oracle
//! binding — `core ← engine ← loop`. The engine's MVP regression registry stays
//! unaware of regions; this discovery-loop data lives here.
//!
//! What "admission" adds on top of the engine's capability gate:
//! - **Parameter bounds (stage 2):** the template's declared `ParamSpecSet`
//!   (`smash_engine::bounds`, looked up by handle) must accept the proposal's params —
//!   checked **first** (admission-funnel §2), via [`crate::param_check`], else
//!   [`AdmissionDenial::ParamOutOfBounds`]. A template with no declared bounds is
//!   *unenforced* for this increment (permissive); declaring a `ParamSpecSet` opts a
//!   template into bounds checking.
//! - **Region-assignability (M7):** a candidate names exactly one intended region;
//!   admission confirms that region is a member of the declared partition for the
//!   candidate's technique handle, else [`AdmissionDenial::NotRegionAssignable`].
//! - **Oracle-binding (N7):** the handle is looked up in the engine [`Registry`]. A
//!   registered technique carries a validated [`OracleRef`] → admitted normally. An
//!   unregistered handle has **no validated oracle** → admitted only as *exploratory*:
//!   it may be explored but its best achievable verdict is `Inconclusive`, never
//!   `Fail`. This is a cap, not a denial.

use crate::ports::{AdmissionDenial, CandidateProposal};
use crate::RegionId;
use smash_core::fighter::OracleRef;
use smash_engine::bounds::ParamSpecRegistry;
use smash_engine::registry::{Registry, TechniqueHandle};
use std::collections::BTreeMap;

/// The declared, enumerated region partition for one technique handle, with each
/// region's `adequacy_target` (the dispatched-probe count that makes a region
/// `sample-resolved`, P3 §0.2). Fixed for a run and recorded in the bundle.
#[derive(Clone, Debug, Default)]
pub struct RegionPartition {
    regions: Vec<RegionId>,
    adequacy: BTreeMap<RegionId, u64>,
}

impl RegionPartition {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare a region with its adequacy target. Builder-style; idempotent on the
    /// region list, last-writer-wins on the adequacy target.
    pub fn with_region(mut self, region: RegionId, adequacy_target: u64) -> Self {
        if !self.regions.contains(&region) {
            self.regions.push(region.clone());
        }
        self.adequacy.insert(region, adequacy_target);
        self
    }

    /// The enumerated regions, in declaration order.
    pub fn regions(&self) -> &[RegionId] {
        &self.regions
    }

    pub fn contains(&self, region: &RegionId) -> bool {
        self.adequacy.contains_key(region)
    }

    pub fn adequacy_target(&self, region: &RegionId) -> Option<u64> {
        self.adequacy.get(region).copied()
    }

    pub fn len(&self) -> usize {
        self.regions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }
}

/// The loop-side region registry: `TechniqueHandle → RegionPartition`.
#[derive(Default)]
pub struct RegionRegistry {
    map: BTreeMap<TechniqueHandle, RegionPartition>,
}

impl RegionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare the region partition for a technique handle.
    pub fn declare(&mut self, handle: TechniqueHandle, partition: RegionPartition) {
        self.map.insert(handle, partition);
    }

    pub fn partition(&self, handle: &TechniqueHandle) -> Option<&RegionPartition> {
        self.map.get(handle)
    }
}

/// A candidate admitted to a region: its region, that region's adequacy target, the
/// resolved oracle binding (if any), and whether it is exploratory-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedRegion {
    pub region: RegionId,
    pub adequacy_target: u64,
    /// The validated oracle binding from the engine registry, or `None` when the
    /// handle is unregistered (exploratory).
    pub oracle: Option<OracleRef>,
    /// N7: `true` when there is no validated oracle binding. The controller caps
    /// such a candidate's verdict at `Inconclusive`, never `Fail`.
    pub exploratory: bool,
}

/// Admit one candidate for a technique handle: parameter bounds (stage 2, first), then
/// region-assignability (M7), then oracle-binding (N7). The capability-gate check
/// (scope/authority/expiry/budget) is the engine's and runs separately; this is the
/// admission layer on top.
pub fn admit_candidate(
    regions: &RegionRegistry,
    engine_registry: &Registry,
    param_specs: &ParamSpecRegistry,
    handle: &TechniqueHandle,
    proposal: &CandidateProposal,
) -> Result<AdmittedRegion, AdmissionDenial> {
    // Stage 2 — parameter bounds, validated first (admission-funnel §1/§2). The
    // template's declared ParamSpecSet, looked up by handle, must accept the proposal's
    // params. A template with no declared bounds is unenforced (permissive) for this
    // increment — declaring a ParamSpecSet opts the template into bounds checking.
    // The §2 key-recompute + poison + reservation are wired in `crate::admission`
    // (stage 2b), which calls this and then recomputes the canonical key from the
    // validated content rather than trusting the proposal's supplied key.
    if let Some(specs) = param_specs.get(handle) {
        crate::param_check::check_params(specs, &proposal.params)
            .map_err(AdmissionDenial::ParamOutOfBounds)?;
    }

    // M7: the intended region must be a member of the handle's declared partition.
    let partition = regions
        .partition(handle)
        .ok_or(AdmissionDenial::NotRegionAssignable)?;
    let adequacy_target = partition
        .adequacy_target(&proposal.intended_region)
        .ok_or(AdmissionDenial::NotRegionAssignable)?;

    // N7: a registered technique has a validated oracle binding; an unregistered
    // handle is admitted only as exploratory (capped at Inconclusive), not denied.
    let (oracle, exploratory) = match engine_registry.get(handle) {
        Some(entry) => (Some(entry.declares().oracle().clone()), false),
        None => (None, true),
    };

    Ok(AdmittedRegion {
        region: proposal.intended_region.clone(),
        adequacy_target,
        oracle,
        exploratory,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CanonicalKey;
    use smash_core::capability::Authority;
    use smash_core::fighter::{
        EvidenceSchema, FighterId, OracleId, OracleKind, OracleRef, OracleVersion, Prerequisite,
        Technique, TechniqueName,
    };
    use smash_engine::bounds::{Charset, ParamSpec, ParamSpecSet};
    use smash_engine::registry::{ApprovedTechnique, Registry, TechniqueHandle, TechniqueVersion};
    use smash_generator::candidate::ParamValue;

    fn handle() -> TechniqueHandle {
        TechniqueHandle::new(
            FighterId::new("taint-launder"),
            TechniqueName::new("encoding-equiv"),
        )
    }

    fn technique() -> Technique {
        Technique::new(
            TechniqueName::new("encoding-equiv"),
            Authority::Mutating,
            OracleRef::new(
                OracleKind::Differential,
                OracleId::new("f-b-taint-oracle"),
                OracleVersion(1),
            ),
            vec![Prerequisite::CanaryBackend],
            EvidenceSchema::new("differential-pair", 1),
            "encoding-laundering of a tainted field",
        )
    }

    struct FullImpl {
        fighter: FighterId,
        declared: Technique,
    }
    impl ApprovedTechnique for FullImpl {
        fn fighter_id(&self) -> &FighterId {
            &self.fighter
        }
        fn technique_name(&self) -> &TechniqueName {
            self.declared.name()
        }
        fn version(&self) -> TechniqueVersion {
            TechniqueVersion(1)
        }
        fn declares(&self) -> &Technique {
            &self.declared
        }
    }

    fn registry_with_handle() -> Registry {
        let mut reg = Registry::new();
        reg.register(Box::new(FullImpl {
            fighter: FighterId::new("taint-launder"),
            declared: technique(),
        }))
        .unwrap();
        reg
    }

    fn region_registry() -> RegionRegistry {
        let mut rr = RegionRegistry::new();
        rr.declare(
            handle(),
            RegionPartition::new()
                .with_region(RegionId("encodings".into()), 8)
                .with_region(RegionId("boundaries".into()), 4),
        );
        rr
    }

    /// No declared bounds — admission is permissive on params for this increment.
    fn no_specs() -> ParamSpecRegistry {
        ParamSpecRegistry::new()
    }

    /// A spec registry that bounds `recipient` to a short ASCII string.
    fn bounded_specs() -> ParamSpecRegistry {
        let mut reg = ParamSpecRegistry::new();
        reg.declare(
            handle(),
            ParamSpecSet::new()
                .with("recipient", ParamSpec::Str { max_len: 32, charset: Charset::AsciiPrintable }),
        )
        .unwrap();
        reg
    }

    fn proposal(region: &str) -> CandidateProposal {
        CandidateProposal {
            key: CanonicalKey("cand-1".into()),
            handle: handle(),
            intended_region: RegionId(region.into()),
            params: BTreeMap::new(),
        }
    }

    fn proposal_with(region: &str, recipient: &str) -> CandidateProposal {
        let mut params = BTreeMap::new();
        params.insert("recipient".to_string(), ParamValue::Str(recipient.into()));
        CandidateProposal {
            key: CanonicalKey("cand-1".into()),
            handle: handle(),
            intended_region: RegionId(region.into()),
            params,
        }
    }

    #[test]
    fn registered_handle_with_valid_region_admits_normally() {
        let admitted = admit_candidate(
            &region_registry(),
            &registry_with_handle(),
            &no_specs(),
            &handle(),
            &proposal("encodings"),
        )
        .unwrap();
        assert_eq!(admitted.region, RegionId("encodings".into()));
        assert_eq!(admitted.adequacy_target, 8);
        assert!(!admitted.exploratory);
        assert_eq!(
            admitted.oracle.unwrap().id(),
            &OracleId::new("f-b-taint-oracle")
        );
    }

    #[test]
    fn region_not_in_partition_is_not_assignable() {
        let err = admit_candidate(
            &region_registry(),
            &registry_with_handle(),
            &no_specs(),
            &handle(),
            &proposal("nonexistent"),
        )
        .unwrap_err();
        assert_eq!(err, AdmissionDenial::NotRegionAssignable);
    }

    #[test]
    fn handle_with_no_partition_is_not_assignable() {
        let empty = RegionRegistry::new();
        let err = admit_candidate(&empty, &registry_with_handle(), &no_specs(), &handle(), &proposal("encodings"))
            .unwrap_err();
        assert_eq!(err, AdmissionDenial::NotRegionAssignable);
    }

    #[test]
    fn unregistered_handle_is_admitted_exploratory_not_denied() {
        let empty_engine = Registry::new();
        let admitted = admit_candidate(
            &region_registry(),
            &empty_engine,
            &no_specs(),
            &handle(),
            &proposal("boundaries"),
        )
        .unwrap();
        assert!(admitted.exploratory);
        assert!(admitted.oracle.is_none());
        assert_eq!(admitted.region, RegionId("boundaries".into()));
        assert_eq!(admitted.adequacy_target, 4);
    }

    #[test]
    fn adequacy_target_is_per_region() {
        let rr = region_registry();
        let p = rr.partition(&handle()).unwrap();
        assert_eq!(p.adequacy_target(&RegionId("encodings".into())), Some(8));
        assert_eq!(p.adequacy_target(&RegionId("boundaries".into())), Some(4));
        assert_eq!(p.adequacy_target(&RegionId("nope".into())), None);
        assert_eq!(p.len(), 2);
    }

    // ── Stage 2: parameter bounds ─────────────────────────────────────────

    #[test]
    fn in_bounds_params_admit_normally() {
        let admitted = admit_candidate(
            &region_registry(),
            &registry_with_handle(),
            &bounded_specs(),
            &handle(),
            &proposal_with("encodings", "landlord"),
        )
        .unwrap();
        assert_eq!(admitted.region, RegionId("encodings".into()));
    }

    #[test]
    fn out_of_bounds_params_are_rejected_before_region() {
        // A recipient over the 32-byte / printable-ASCII bound → ParamOutOfBounds,
        // even though the region would be assignable (params are checked first).
        let err = admit_candidate(
            &region_registry(),
            &registry_with_handle(),
            &bounded_specs(),
            &handle(),
            &proposal_with("encodings", &"x".repeat(40)),
        )
        .unwrap_err();
        assert!(matches!(err, AdmissionDenial::ParamOutOfBounds(_)));
    }

    #[test]
    fn param_bounds_checked_before_region_assignability() {
        // Even an unassignable region must not mask a param-bounds rejection: params
        // are validated first, so the bounds failure wins.
        let err = admit_candidate(
            &region_registry(),
            &registry_with_handle(),
            &bounded_specs(),
            &handle(),
            &proposal_with("nonexistent-region", &"x".repeat(40)),
        )
        .unwrap_err();
        assert!(
            matches!(err, AdmissionDenial::ParamOutOfBounds(_)),
            "params are validated before region-assignability"
        );
    }

    #[test]
    fn undeclared_bounds_are_permissive() {
        // No ParamSpecSet for the handle → param check is skipped (this increment).
        let admitted = admit_candidate(
            &region_registry(),
            &registry_with_handle(),
            &no_specs(),
            &handle(),
            &proposal_with("encodings", &"x".repeat(1000)),
        )
        .unwrap();
        assert_eq!(admitted.region, RegionId("encodings".into()));
    }
}
