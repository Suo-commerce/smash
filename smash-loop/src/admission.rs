//! Admission with the stage-2 dedup lifecycle wired in (P3 §1 step 2; `admission-funnel`
//! spec §2). **This is where stage 2b lands.**
//!
//! [`crate::regions::admit_candidate`] already does the per-candidate checks — parameter
//! bounds first (stage 2), then region-assignability (M7), then oracle-binding (N7). This
//! module wraps it with the §2 dedup ordering that needs *run-scoped* state the free
//! function can't see:
//!
//! 1. **admit_candidate** — params (first), region, oracle binding.
//! 2. **recompute the `CanonicalKey`** from the *validated* content via
//!    [`smash_engine::candidate_key`] — never the generator's supplied key (§2.1): an
//!    untrusted key could alias two different candidates behind one reservation, or split
//!    one candidate across two keys and defeat dedup.
//! 3. **poison check** against the run's [`Quiescence`] (key *or* region) — before any
//!    merge (§2.2): a poisoned key drops, it never merges.
//! 4. **atomic reserve** in the run's [`DedupTable`]; a duplicate merges (no re-dispatch),
//!    a first sighting reserves.
//!
//! Only the **reserve** half lives here. The **commit / mark_uncertain** half is driven by
//! the controller after the dispatch resolves — `DedupTable::commit` on a clean
//! resolution, `mark_uncertain` on an `Unresolved` effect, in lockstep with the quiescence
//! poison the barrier records on the same event.

use crate::dedup::{DedupOutcome, DedupTable};
use crate::ports::{AdmissionDenial, CandidateProposal};
use crate::quiescence::Quiescence;
use crate::regions::{admit_candidate, AdmittedRegion, RegionRegistry};
use crate::CanonicalKey;
use smash_engine::bounds::ParamSpecRegistry;
use smash_engine::candidate_key::candidate_key;
use smash_engine::registry::Registry;

/// A candidate that passed admission and holds a fresh within-run reservation: the
/// **recomputed** canonical key (the one dedup and poison bind to) and its admitted
/// region. The controller plans the dispatch (probe + write control) from this and, on
/// resolution, commits or marks-uncertain the reservation under [`key`](Self::key).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AdmittedCandidate {
    pub key: CanonicalKey,
    pub region: AdmittedRegion,
}

/// The outcome of admitting one proposal through the dedup lifecycle. Only
/// [`Admitted`](AdmitOutcome::Admitted) authorizes a dispatch.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AdmitOutcome {
    /// First sighting of this validated candidate — reserved; proceed to dispatch.
    Admitted(AdmittedCandidate),
    /// A duplicate of a candidate already in flight / resolved / held — merged into its
    /// reservation, no re-dispatch (carries which merge it was).
    Merged(DedupOutcome),
    /// The candidate's key or region is poisoned — dropped before any merge (§2.2). The
    /// caller records a `RejectedAtAdmission` coverage fact.
    DroppedPoisoned,
    /// admit_candidate refused it (param bounds / unassignable region) — a plan-level
    /// denial (N3), never an attempt. The caller records a `planner_denials` count.
    Denied(AdmissionDenial),
}

/// Recompute the content-only canonical key from a proposal's **validated** handle +
/// params (admission-funnel §2.1). The engine owns the mint; the loop lowers the
/// generator's `ParamValue` tree to JSON ([`crate::metamorphic::params_to_json`]) and
/// reads the handle's identity strings.
pub fn recompute_key(proposal: &CandidateProposal) -> CanonicalKey {
    let params_json = crate::metamorphic::params_to_json(&proposal.params);
    CanonicalKey(candidate_key(
        proposal.handle.fighter.as_str(),
        proposal.handle.technique.as_str(),
        &params_json,
    ))
}

/// Admit one proposal through the full §2 ordering. `provenance` tags this sighting in
/// the dedup table for audit (e.g. the proposal's ordinal / epoch).
pub fn admit_with_dedup(
    regions: &RegionRegistry,
    engine_registry: &Registry,
    param_specs: &ParamSpecRegistry,
    quiescence: &Quiescence,
    dedup: &mut DedupTable,
    proposal: &CandidateProposal,
    provenance: String,
) -> AdmitOutcome {
    // 1. Params (first), region-assignability, oracle-binding. A denial is plan-level.
    let region = match admit_candidate(
        regions,
        engine_registry,
        param_specs,
        &proposal.handle,
        proposal,
    ) {
        Ok(r) => r,
        Err(denial) => return AdmitOutcome::Denied(denial),
    };

    // 2. Recompute the key from the validated content — never trust the supplied key.
    let key = recompute_key(proposal);

    // 3. Poison precedes merge (§2.2): key OR region poisoned → drop.
    let poisoned =
        quiescence.is_key_poisoned(&key) || quiescence.is_region_poisoned(&region.region);

    // 4. Atomic reserve; merge a duplicate, drop a poisoned key.
    match dedup.reserve(&key, poisoned, provenance) {
        DedupOutcome::Reserved => AdmitOutcome::Admitted(AdmittedCandidate { key, region }),
        DedupOutcome::DroppedPoisoned => AdmitOutcome::DroppedPoisoned,
        merged => AdmitOutcome::Merged(merged),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::regions::{RegionPartition, RegionRegistry};
    use crate::RegionId;
    use smash_core::capability::Authority;
    use smash_core::fighter::{
        EvidenceSchema, FighterId, OracleId, OracleKind, OracleRef, OracleVersion, Prerequisite,
        Technique, TechniqueName,
    };
    use smash_engine::bounds::{Charset, ParamSpec, ParamSpecSet, ParamSpecRegistry};
    use smash_engine::registry::{ApprovedTechnique, Registry, TechniqueHandle, TechniqueVersion};
    use smash_generator::candidate::ParamValue;
    use std::collections::BTreeMap;

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

    fn no_specs() -> ParamSpecRegistry {
        ParamSpecRegistry::new()
    }

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

    /// A proposal with an arbitrary (advisory) supplied key, the shared handle, a region,
    /// and a `recipient` param.
    fn proposal(supplied_key: &str, region: &str, recipient: &str) -> CandidateProposal {
        let mut params = BTreeMap::new();
        params.insert("recipient".to_string(), ParamValue::Str(recipient.into()));
        CandidateProposal {
            key: CanonicalKey(supplied_key.into()),
            handle: handle(),
            intended_region: RegionId(region.into()),
            params,
        }
    }

    #[test]
    fn fresh_candidate_is_admitted_and_reserved() {
        let (rr, er, ps) = (region_registry(), registry_with_handle(), no_specs());
        let q = Quiescence::new(3);
        let mut dedup = DedupTable::new();
        let p = proposal("advisory", "encodings", "landlord");
        match admit_with_dedup(&rr, &er, &ps, &q, &mut dedup, &p, "p1".into()) {
            AdmitOutcome::Admitted(a) => {
                assert_eq!(a.region.region, RegionId("encodings".into()));
                assert!(dedup.is_reserved(&a.key));
                assert_eq!(a.key, recompute_key(&p));
            }
            other => panic!("expected Admitted, got {other:?}"),
        }
    }

    #[test]
    fn supplied_key_is_not_trusted_duplicates_collapse_on_recomputed_key() {
        // Two proposals with DIFFERENT supplied keys but identical handle+params must
        // recompute to the SAME key — the second merges, proving §2.1.
        let (rr, er, ps) = (region_registry(), registry_with_handle(), no_specs());
        let q = Quiescence::new(3);
        let mut dedup = DedupTable::new();
        let a = proposal("lie-1", "encodings", "landlord");
        let b = proposal("lie-2", "encodings", "landlord");
        assert!(matches!(
            admit_with_dedup(&rr, &er, &ps, &q, &mut dedup, &a, "a".into()),
            AdmitOutcome::Admitted(_)
        ));
        assert_eq!(
            admit_with_dedup(&rr, &er, &ps, &q, &mut dedup, &b, "b".into()),
            AdmitOutcome::Merged(DedupOutcome::MergedInFlight),
        );
    }

    #[test]
    fn a_poisoned_region_drops_before_merge() {
        let (rr, er, ps) = (region_registry(), registry_with_handle(), no_specs());
        let mut q = Quiescence::new(3);
        // Poison the "encodings" region (via some unrelated key).
        q.record_unresolved(CanonicalKey("other".into()), RegionId("encodings".into()), 0);
        let mut dedup = DedupTable::new();
        let p = proposal("advisory", "encodings", "landlord");
        assert_eq!(
            admit_with_dedup(&rr, &er, &ps, &q, &mut dedup, &p, "p1".into()),
            AdmitOutcome::DroppedPoisoned,
        );
        assert!(!dedup.is_reserved(&recompute_key(&p)), "a dropped candidate never reserves");
    }

    #[test]
    fn a_poisoned_key_drops_even_in_an_unpoisoned_region() {
        let (rr, er, ps) = (region_registry(), registry_with_handle(), no_specs());
        let mut q = Quiescence::new(3);
        let p = proposal("advisory", "encodings", "landlord");
        // Poison this candidate's recomputed key (in a different region, so only the
        // key-poison path can fire).
        q.record_unresolved(recompute_key(&p), RegionId("boundaries".into()), 0);
        let mut dedup = DedupTable::new();
        assert_eq!(
            admit_with_dedup(&rr, &er, &ps, &q, &mut dedup, &p, "p1".into()),
            AdmitOutcome::DroppedPoisoned,
        );
    }

    #[test]
    fn out_of_bounds_params_are_denied() {
        let (rr, er, ps) = (region_registry(), registry_with_handle(), bounded_specs());
        let q = Quiescence::new(3);
        let mut dedup = DedupTable::new();
        let p = proposal("advisory", "encodings", &"x".repeat(40)); // over the 32-byte bound
        match admit_with_dedup(&rr, &er, &ps, &q, &mut dedup, &p, "p1".into()) {
            AdmitOutcome::Denied(AdmissionDenial::ParamOutOfBounds(_)) => {}
            other => panic!("expected ParamOutOfBounds, got {other:?}"),
        }
    }

    #[test]
    fn an_unassignable_region_is_denied() {
        let (rr, er, ps) = (region_registry(), registry_with_handle(), no_specs());
        let q = Quiescence::new(3);
        let mut dedup = DedupTable::new();
        let p = proposal("advisory", "nonexistent", "landlord");
        assert_eq!(
            admit_with_dedup(&rr, &er, &ps, &q, &mut dedup, &p, "p1".into()),
            AdmitOutcome::Denied(AdmissionDenial::NotRegionAssignable),
        );
    }

    #[test]
    fn an_exploratory_handle_still_admits_and_reserves() {
        // No registered engine technique → admit_candidate returns exploratory (capped
        // at Inconclusive), NOT a denial, so dedup still reserves it.
        let (rr, empty_engine, ps) = (region_registry(), Registry::new(), no_specs());
        let q = Quiescence::new(3);
        let mut dedup = DedupTable::new();
        let p = proposal("advisory", "boundaries", "landlord");
        match admit_with_dedup(&rr, &empty_engine, &ps, &q, &mut dedup, &p, "p1".into()) {
            AdmitOutcome::Admitted(a) => {
                assert!(a.region.exploratory);
                assert!(a.region.oracle.is_none());
            }
            other => panic!("expected exploratory Admitted, got {other:?}"),
        }
    }

    #[test]
    fn a_clean_duplicate_after_commit_merges_into_the_execution() {
        let (rr, er, ps) = (region_registry(), registry_with_handle(), no_specs());
        let q = Quiescence::new(3);
        let mut dedup = DedupTable::new();
        let p = proposal("advisory", "encodings", "landlord");
        let key = match admit_with_dedup(&rr, &er, &ps, &q, &mut dedup, &p, "a".into()) {
            AdmitOutcome::Admitted(a) => a.key,
            other => panic!("expected Admitted, got {other:?}"),
        };
        // Controller resolves the dispatch cleanly → commit under the recomputed key.
        assert!(dedup.commit(&key, "exec-1".into()));
        // A later duplicate merges into that execution, no re-dispatch.
        assert_eq!(
            admit_with_dedup(&rr, &er, &ps, &q, &mut dedup, &p, "b".into()),
            AdmitOutcome::Merged(DedupOutcome::MergedResolved("exec-1".into())),
        );
    }
}
