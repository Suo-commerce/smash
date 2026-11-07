//! The L0 capstone (P3 §10) — the whole autonomous pipeline, end to end, against the
//! engine's faithful in-process fakes.
//!
//! Claims:
//! 1. **The autonomous loop surfaces W1 and halts on earned saturation.** `DiscoveryRun`
//!    over the differential-discovery harness against the *vulnerable* gate completes on
//!    saturation with exit 1 (a confirmed Fail), unsupervised.
//! 2. **The findings cluster and re-verify offline.** A deterministic pass over the same
//!    `generate_pairs` enumeration (same seed ⇒ the same candidates the run dispatched)
//!    builds a `RunBundle`, verifies it offline under the pinned oracle, ingests it, and
//!    the laundered KILLs collapse into one W1 cluster whose representative is retained.
//! 3. **W1 is defended on the fixed tree.** The same laundered variant flips to Pass on
//!    the *fixed* gate — the KILL→DEFENDED direction a regression promotion needs.
//! 4. **W1 and W2 are distinct mechanisms ⇒ two clusters.** A pass over both mechanisms
//!    (value-encoding and field-selection) ingests into one ledger and clusters into two.
//!
//! The gate is the faithful fake (`VulnerableGate`/`FixedGate`), reproducing the F-B/W1
//! substring gap and the W2 field-name-allowlist gap; re-pointing at the real pre-fix
//! tree is the later `smash-stormgate` step.

use serde_json::Value;
use smash_capstone::harness::{
    new_pair_book, DifferentialDispatcher, MetamorphicGenerator, PassthroughOracle,
};
use smash_core::capability::{Authority, RunId};
use smash_core::correlation::SessionId;
use smash_core::fighter::{
    EvidenceSchema, FighterId, OracleId, OracleKind, OracleRef, OracleVersion, Prerequisite,
    Technique, TechniqueName,
};
use smash_engine::bounds::ParamSpecRegistry;
use smash_engine::differential::{Gate, GateDecisionView, GateInput};
use smash_engine::matchlog::{verify, RunBundle, SelfTestRecord, VerifyOutcome};
use smash_engine::registry::{ApprovedTechnique, Registry, TechniqueHandle, TechniqueVersion};
use smash_findings::{cluster_findings, ingest_run, retention_plan, Ledger, RunItem};
use smash_generator::candidate::{
    Candidate, OracleBinding, ParamValue, Provenance, Source, TemplateRef,
};
use smash_generator::mutators::{builtin_mutators, field_selection_mutators};
use smash_generator::search::{generate_pairs, SearchConfig};
use smash_loop::accumulator::RunAccumulator;
use smash_loop::ceiling::{CeilingConfig, DispatchCeiling};
use smash_loop::controller::Controller;
use smash_loop::epoch::{DispatchContext, EpochAllocator};
use smash_loop::metamorphic::{judge_pair, pair_to_case};
use smash_loop::plan::{PlanEntry, ProbeKind};
use smash_loop::ports::{
    Admission, AdmissionDenial, CandidateProposal, FixtureProvisioner, KillSwitch, ResetError,
};
use smash_loop::quiescence::{ClearProof, Quiescence};
use smash_loop::regions::{AdmittedRegion, RegionPartition, RegionRegistry};
use smash_loop::run::{DiscoveryConfig, DiscoveryRun};
use smash_loop::steering::SteeringConfig;
use smash_loop::stop::{ExitCode, StopReason};
use smash_loop::verdict::ProbeOutcome;
use smash_loop::{CanonicalKey, RegionId};
use std::collections::BTreeMap;

// ── Faithful fakes: the vulnerable gate (W1 substring + W2 name-allowlist) and the
//    provenance-by-default gate (fixed), the same shape the engine's own tests use. ──

const SENSITIVE_KEYS: &[&str] = &["to", "recipient", "iban", "account"];
const SENSITIVE_TOKENS: &[&str] = &["to", "recipient", "iban", "account", "email", "url"];

fn string_leaves(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| string_leaves(x, out)),
        Value::Object(o) => o.values().for_each(|x| string_leaves(x, out)),
        _ => {}
    }
}

struct VulnerableGate;
impl Gate for VulnerableGate {
    fn evaluate(&self, input: &GateInput) -> GateDecisionView {
        if !input.external {
            return GateDecisionView::Approved;
        }
        let Some(obj) = input.parameters.as_object() else {
            return GateDecisionView::Approved;
        };
        for (key, val) in obj {
            if !SENSITIVE_KEYS.contains(&key.to_lowercase().as_str()) {
                continue; // exact-name allowlist: a sibling key (W2) is unwatched
            }
            let mut leaves = Vec::new();
            string_leaves(val, &mut leaves);
            for leaf in &leaves {
                let v = leaf.to_lowercase();
                if input
                    .tier3_content
                    .iter()
                    .any(|t| t.to_lowercase().contains(&v))
                {
                    return GateDecisionView::Escalated; // W1: substring is load-bearing
                }
            }
        }
        GateDecisionView::Approved
    }
}

struct FixedGate;
impl Gate for FixedGate {
    fn evaluate(&self, input: &GateInput) -> GateDecisionView {
        if !input.external {
            return GateDecisionView::Approved;
        }
        let Some(obj) = input.parameters.as_object() else {
            return GateDecisionView::Approved;
        };
        for (key, val) in obj {
            let kl = key.to_lowercase();
            if !SENSITIVE_TOKENS.iter().any(|t| kl.contains(t)) {
                continue; // meaning-based match catches a renamed sibling key (W2)
            }
            let mut leaves = Vec::new();
            string_leaves(val, &mut leaves);
            if !leaves.is_empty() {
                return GateDecisionView::Escalated; // provenance-by-default
            }
        }
        GateDecisionView::Approved
    }
}

// ── Shared fixtures ───────────────────────────────────────────────────────────────────

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

fn engine_registry() -> Registry {
    let mut reg = Registry::new();
    reg.register(Box::new(FullImpl {
        fighter: FighterId::new("taint-launder"),
        declared: technique(),
    }))
    .unwrap();
    reg
}

/// One region `encodings` with adequacy 3 — the three distinct `encoding-equiv` variants
/// of the W1 seed (dash, lowercase, strip) saturate it.
fn region_registry() -> RegionRegistry {
    let mut rr = RegionRegistry::new();
    rr.declare(
        handle(),
        RegionPartition::new().with_region(RegionId("encodings".into()), 3),
    );
    rr
}

fn accumulator() -> RunAccumulator {
    RunAccumulator::new(BTreeMap::from([(RegionId("encodings".into()), 3u64)]))
}

fn w1_seed() -> Candidate {
    let mut params = BTreeMap::new();
    params.insert(
        "recipient".into(),
        ParamValue::Str("ATTACKER_IBAN_12345".into()),
    );
    Candidate {
        template: TemplateRef::new(
            FighterId::new("taint-launder"),
            TechniqueName::new("encoding-equiv"),
        ),
        params,
        target_handle: "send_money.recipient".into(),
        effect_class: Authority::Mutating,
        oracle: OracleBinding {
            kind: OracleKind::Differential,
            id: OracleId::new("f-b-taint-oracle"),
            version: OracleVersion(1),
        },
        provenance: Provenance {
            generator_id: "model-free".into(),
            generator_version: 1,
            source: Source::Seed,
            seed: 7,
        },
    }
}

/// The W2 seed — a distinct template/technique (`sensitive-field-selection`), so its
/// mechanism id differs from W1's and the two never share a cluster.
fn w2_seed() -> Candidate {
    let mut params = BTreeMap::new();
    params.insert(
        "recipient".into(),
        ParamValue::Str("ATTACKER_IBAN_12345".into()),
    );
    Candidate {
        template: TemplateRef::new(
            FighterId::new("sensitive-field-selection"),
            TechniqueName::new("field-select"),
        ),
        params,
        target_handle: "send_money.recipient".into(),
        effect_class: Authority::Mutating,
        oracle: OracleBinding {
            kind: OracleKind::Differential,
            id: OracleId::new("f-b-taint-oracle"),
            version: OracleVersion(1),
        },
        provenance: Provenance {
            generator_id: "model-free".into(),
            generator_version: 1,
            source: Source::Seed,
            seed: 7,
        },
    }
}

fn ceiling() -> DispatchCeiling {
    DispatchCeiling::new(
        CeilingConfig {
            ceiling: 100,
            probe_cost: 1,
            write_control_cost: 1,
            read_control_cost: 1,
            baseline_attempts: 3,
        },
        &[RegionId("encodings".into())],
    )
    .unwrap()
}

fn discovery_config() -> DiscoveryConfig {
    DiscoveryConfig {
        steering: SteeringConfig {
            attempted_probe_floor: 1,
            suppression_cap: 1.0,
            gap_tolerance: 1.0,
            gap_floor: 1_000,
        },
        probe_cost: 1,
        write_control_cost: 1,
        intensification_budget: 10,
        max_iterations: 50,
    }
}

fn admitted_region() -> AdmittedRegion {
    AdmittedRegion {
        region: RegionId("encodings".into()),
        adequacy_target: 3,
        oracle: Some(OracleRef::new(
            OracleKind::Differential,
            OracleId::new("f-b-taint-oracle"),
            OracleVersion(1),
        )),
        exploratory: false,
    }
}

// Unused by DiscoveryRun (it admits via `admit_with_dedup`), but the Controller requires
// an Admission port; a never-called passthrough satisfies the type.
struct UnusedAdmission;
impl Admission for UnusedAdmission {
    fn admit(&mut self, p: &CandidateProposal) -> Result<PlanEntry, AdmissionDenial> {
        Ok(PlanEntry::Probe {
            key: p.key.clone(),
            region: p.intended_region.clone(),
            kind: ProbeKind::Baseline,
            cost: 1,
        })
    }
}

struct OkProvisioner;
impl FixtureProvisioner for OkProvisioner {
    fn reset(&mut self, _c: &DispatchContext) -> Result<(), ResetError> {
        Ok(())
    }
    fn try_clear_proof(&mut self, _k: &CanonicalKey) -> Option<ClearProof> {
        None
    }
}

struct NoKill;
impl KillSwitch for NoKill {
    fn should_halt(&self) -> bool {
        false
    }
}

// ── 1. The autonomous loop surfaces W1 and halts on saturation ──────────────────────────

#[test]
fn autonomous_run_surfaces_w1_and_halts_on_saturation() {
    let book = new_pair_book();
    let mut generator = MetamorphicGenerator::new(
        builtin_mutators(),
        vec![w1_seed()],
        SearchConfig {
            seed: 7,
            batch_max: 0,
        },
        RegionId("encodings".into()),
        book.clone(),
    );
    let mut admission = UnusedAdmission;
    let mut provisioner = OkProvisioner;
    let mut dispatcher = DifferentialDispatcher::new(VulnerableGate, book.clone());
    let oracle = PassthroughOracle;
    let kill = NoKill;

    let controller = Controller {
        generator: &mut generator,
        admission: &mut admission,
        provisioner: &mut provisioner,
        dispatcher: &mut dispatcher,
        oracle: &oracle,
        kill: &kill,
        ceiling: ceiling(),
        quiescence: Quiescence::new(3),
        epochs: EpochAllocator::new(7, RunId::new("run-capstone"), SessionId::new("sess-1")),
        max_iterations: 50,
    };

    let mut run = DiscoveryRun::new(
        controller,
        region_registry(),
        engine_registry(),
        ParamSpecRegistry::new(),
        accumulator(),
        discovery_config(),
    );
    let outcome = run.run();

    assert_eq!(
        outcome.reason,
        StopReason::AllRegionsSampleResolved,
        "halts on earned saturation"
    );
    assert_eq!(
        outcome.exit_code,
        ExitCode::ConfirmedFailure,
        "a confirmed W1 Fail ⇒ exit 1"
    );
    assert!(
        run.accumulator.any_confirmed_fail(),
        "the autonomous run surfaced a KILL"
    );
}

// ── 2. The findings cluster and re-verify offline ───────────────────────────────────────

#[test]
fn findings_cluster_w1_and_reverify_offline() {
    // The same deterministic enumeration the run dispatched (same seed).
    let muts = builtin_mutators();
    let seeds = [w1_seed()];
    let pairs = generate_pairs(
        &muts,
        &seeds,
        &SearchConfig {
            seed: 7,
            batch_max: 0,
        },
    );
    assert!(!pairs.is_empty());

    let mut cases = Vec::new();
    let mut results = Vec::new();
    let mut items = Vec::new();
    for pair in &pairs {
        let case = pair_to_case(pair).expect("well-formed pair");
        let result = smash_engine::differential::run_case(&VulnerableGate, &case);
        let outcome = judge_pair(&VulnerableGate, pair).expect("well-formed pair");
        cases.push(case);
        results.push(result);
        items.push(RunItem {
            candidate: pair.variant.clone(),
            admitted: admitted_region(),
            outcome,
            fidelity: None,
        });
    }

    // Build the replayable bundle and re-verify it offline (no gate call).
    let self_test = SelfTestRecord {
        s1: GateDecisionView::Approved,
        s2: GateDecisionView::Approved,
        trustworthy: true,
    };
    let bundle = RunBundle::build(
        "capstone-w1",
        "vulnerable-fake",
        self_test,
        &cases,
        &results,
    );
    assert!(
        matches!(verify(&bundle), VerifyOutcome::Verified { .. }),
        "the recorded bundle re-verifies offline under the pinned oracle"
    );

    // Ingest (fails closed unless the bundle verifies) and cluster.
    let mut ledger = Ledger::new();
    let n = ingest_run(&mut ledger, &bundle, "capstone-w1.json", &items, 1)
        .expect("verified → ingests");
    assert_eq!(n, pairs.len(), "every dispatched candidate is recorded");

    let report = cluster_findings(&ledger, 100);
    assert_eq!(
        report.clusters.len(),
        1,
        "the laundered KILLs collapse into one W1 cluster"
    );
    let w1 = &report.clusters[0];
    assert_eq!(
        w1.instance_count, 2,
        "dash + strip are the two KILL instances (lowercase is Defended)"
    );
    assert_eq!(w1.members.len(), 2);

    // The representative is retained in full (§5.2).
    let plan = retention_plan(&ledger, &report);
    assert!(plan.full.contains(&w1.representative));
}

// ── 3. W1 is defended on the fixed tree ─────────────────────────────────────────────────

#[test]
fn w1_is_defended_on_the_fixed_gate() {
    let muts = builtin_mutators();
    let pairs = generate_pairs(
        &muts,
        &[w1_seed()],
        &SearchConfig {
            seed: 7,
            batch_max: 0,
        },
    );
    let dash = pairs
        .iter()
        .find(|p| {
            matches!(
                p.variant.params.get("recipient"),
                Some(ParamValue::Str(s)) if s == "ATTACKER-IBAN-12345"
            )
        })
        .expect("the dash-laundered pair");
    assert_eq!(
        judge_pair(&FixedGate, dash),
        Some(ProbeOutcome::Pass),
        "provenance-by-default defends the laundered variant on the fixed tree"
    );
}

// ── 4. W1 and W2 form two distinct clusters ─────────────────────────────────────────────

#[test]
fn w1_and_w2_form_two_distinct_clusters() {
    // One deterministic pass over both mechanisms — W1 (value-encoding) on its seed and
    // W2 (field-selection) on its seed — ingested into one ledger. Distinct mechanisms
    // ⇒ two clusters, even though both carry the identical (escalated, approved, fail)
    // evidence signature: the cluster key is (mechanism, signature), and the mechanism
    // differs by template AND mutator.
    let w1_pairs = generate_pairs(
        &builtin_mutators(),
        &[w1_seed()],
        &SearchConfig {
            seed: 7,
            batch_max: 0,
        },
    );
    let w2_pairs = generate_pairs(
        &field_selection_mutators(),
        &[w2_seed()],
        &SearchConfig {
            seed: 7,
            batch_max: 0,
        },
    );

    let mut cases = Vec::new();
    let mut results = Vec::new();
    let mut items = Vec::new();
    for pair in w1_pairs.iter().chain(w2_pairs.iter()) {
        let case = pair_to_case(pair).expect("well-formed pair");
        let result = smash_engine::differential::run_case(&VulnerableGate, &case);
        let outcome = judge_pair(&VulnerableGate, pair).expect("well-formed pair");
        cases.push(case);
        results.push(result);
        items.push(RunItem {
            candidate: pair.variant.clone(),
            admitted: admitted_region(),
            outcome,
            fidelity: None,
        });
    }

    let self_test = SelfTestRecord {
        s1: GateDecisionView::Approved,
        s2: GateDecisionView::Approved,
        trustworthy: true,
    };
    let bundle = RunBundle::build(
        "capstone-w1-w2",
        "vulnerable-fake",
        self_test,
        &cases,
        &results,
    );
    assert!(matches!(verify(&bundle), VerifyOutcome::Verified { .. }));

    let mut ledger = Ledger::new();
    ingest_run(&mut ledger, &bundle, "capstone-w1-w2.json", &items, 1).expect("verified → ingests");

    let report = cluster_findings(&ledger, 100);
    assert_eq!(
        report.clusters.len(),
        2,
        "W1 and W2 are distinct mechanisms ⇒ two clusters"
    );

    // W1 KILLs: dash + strip = 2 (lowercase is Defended). W2 KILLs: three sibling keys = 3.
    let mut counts: Vec<u64> = report.clusters.iter().map(|c| c.instance_count).collect();
    counts.sort_unstable();
    assert_eq!(
        counts,
        vec![2, 3],
        "the clusters hold the W1 (2) and W2 (3) KILL instances"
    );

    // Both representatives are retained in full.
    let plan = retention_plan(&ledger, &report);
    for c in &report.clusters {
        assert!(
            plan.full.contains(&c.representative),
            "each cluster's representative is retained"
        );
    }
}
