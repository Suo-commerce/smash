//! The `CandidateRecord` schema — one row of the ledger.
//!
//! Every field is serde-native. Fields that mirror a core-only (non-serde) type —
//! the canonical key, the template handle, the oracle binding, the effect class — are
//! stored as their stable string rendering, exactly as `smash_engine::matchlog`
//! stores a mirror of a core `Verdict`. Step 2 (ingest) adds a projection constructor
//! `from_admission(&Candidate, &AdmittedRegion, …)`; here the shapes stand alone so
//! the schema, dedup, and lifecycle can be built and tested with no `smash-*` crate.
//!
//! **Severity is deliberately not a field.** It is a property of the technique, not
//! the candidate instance, and is looked up by `TechniqueHandle` from the reviewed
//! registry at ranking time (decision 4, `specs/findings-management.md` §9). An
//! untrusted proposer must never be able to assert the importance triage acts on.
//!
//! **Mechanism id and evidence signature are likewise trusted, not candidate-asserted.**
//! The registered clustering predicate (autonomous-loop §7, `crate::cluster`) groups on
//! `mechanism` + `evidence_signature`; both are populated at ingest from the candidate's
//! template/provenance and the *verified* bundle's recorded decisions — never supplied by
//! the generator, for the same reason severity is not. They are `#[serde(default)]` so a
//! ledger written before they existed still loads (empty = unproven = never clusters).

use serde::{Deserialize, Serialize};

/// The dedup identity: the canonical candidate key, content-only and
/// provenance-excluded, stored as its stable string form
/// (`smash_generator::candidate::CanonicalKey.0`). Two candidates with identical
/// content but different provenance share this key and must dedupe together.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct CandidateKey(pub String);

/// An advisory root-cause grouping (§3). Assigned/confirmed by a human during triage;
/// suggestions are never auto-merged.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct ClusterId(pub String);

/// The mechanism identity of a finding — the `(template, mutator, transform)` triple the
/// registered clustering predicate groups on (autonomous-loop §7, `crate::cluster`).
///
/// Populated at ingest from the candidate's template + provenance; **never
/// candidate-asserted** (the untrusted proposer must not control how its output
/// clusters, the same posture as severity). `transform` is the transform *class* —
/// currently the mutator id, so every encoding under one mutator shares a mechanism and
/// the evidence signature is what separates distinct faults; a finer transform id can
/// split it later without changing the predicate's shape.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default, Serialize, Deserialize)]
pub struct MechanismId {
    pub template: String,
    pub mutator: String,
    pub transform: String,
}

impl MechanismId {
    /// A mechanism with only its template known (mutator/transform empty) — the default a
    /// freshly-surfaced record carries until ingest fills it from the candidate.
    pub fn from_template(template: impl Into<String>) -> Self {
        MechanismId {
            template: template.into(),
            mutator: String::new(),
            transform: String::new(),
        }
    }
}

/// A handle to the pinned, offline-verifiable evidence bundle — a reference, never a
/// copy of the evidence. `digest` is the bundle's own content hash
/// (`smash_engine::matchlog::RunBundle.digest`), recorded so a tampered or swapped
/// bundle is detectable without re-reading it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BundleRef {
    pub path: String,
    pub digest: String,
}

/// The §4 admission outcome for this candidate. A rejected or denied candidate is
/// still a row: **unexecuted coverage, never a pass.**
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum AdmissionOutcome {
    /// Admitted to a region. `exploratory` mirrors the loop's N7 cap: an
    /// unregistered-handle candidate has no validated oracle, so its verdict is
    /// capped at `Inconclusive` and it can **never** promote to a finding.
    Admitted {
        region: String,
        adequacy_target: u64,
        exploratory: bool,
    },
    /// Rejected at admission (schema / param-bounds / effect-class / dedup).
    Rejected { reason: String },
    /// Denied by the capability gate (off-scope / over-ceiling / expired / budget).
    Denied { reason: String },
}

impl AdmissionOutcome {
    /// Whether this candidate ever ran (an `Admitted` candidate may dispatch; a
    /// rejected/denied one is unexecuted coverage).
    pub fn was_admitted(&self) -> bool {
        matches!(self, AdmissionOutcome::Admitted { .. })
    }

    /// N7: an admitted-but-exploratory candidate is capped at `Inconclusive` and can
    /// never become a finding.
    pub fn is_exploratory(&self) -> bool {
        matches!(self, AdmissionOutcome::Admitted { exploratory: true, .. })
    }
}

/// The probe's recorded outcome, read from the bundle — the projection of the loop's
/// `ProbeOutcome` / the engine's core `Verdict`.
///
/// All four outcomes are recorded, because a `Defended` run is a *coverage fact*, not
/// a blank (the Owly lesson, §5): the coverage view needs the defendeds to say what
/// was searched. This is a deliberate, documented widening of §1's terse
/// "KILL | Inconclusive" — only [`Kill`](VerdictClass::Kill) is ever *promotable* to a
/// finding, and a `Defended` means "no divergence observed," never "secure" (oracle
/// asymmetry). Promotion logic keys off `Kill`; coverage keys off all four.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictClass {
    /// Engine `Verdict::Fail` — an enforcement gap. The only promotable outcome.
    Kill,
    /// Engine `Verdict::Pass` — the probe was withheld. Coverage, not "secure".
    Defended,
    /// Engine `Verdict::Inconclusive` — no verdict the differential can speak to.
    Inconclusive,
    /// Engine `Verdict::Error` — invalid fixture (e.g. control did not withhold).
    Error,
}

impl VerdictClass {
    /// Only a `Kill` can be promoted to a finding (oracle asymmetry).
    pub fn is_promotable(self) -> bool {
        matches!(self, VerdictClass::Kill)
    }
}

/// How solid the evidence behind a `Kill` is — the Aegloss fidelity lesson made a
/// first-class field (§9). A `Kill` confirmed by a state/canary receipt outranks one
/// inferred only from a response code.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceFidelity {
    /// The effect was confirmed by a fixture state snapshot / canary receipt.
    EffectConfirmed,
    /// The decision was read from the response only (no effect receipt) — the §4
    /// stage-5 gap. Suggestive, not confirmed.
    ResponseOnly,
    /// No usable fidelity signal (e.g. the probe was inconclusive).
    Inconclusive,
}

/// Provenance, mirrored serde-native from `smash_generator::candidate::Provenance`.
/// Enough to replay, not regenerate. Several variants may share one record under the
/// same canonical key (same content, different seed/source).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub generator_id: String,
    pub generator_version: u32,
    /// Rendered `Source` (e.g. `"seed"`, `"mutation:encoding-equiv"`, `"cve:CVE-…"`).
    pub source: String,
    pub seed: u64,
}

/// Why a candidate was dispositioned `Rejected` during triage (distinct from
/// admission rejection — this is a human triage verdict on a candidate that ran).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    FalsePositive,
    ByDesign,
    OutOfScope,
}

/// The lifecycle state of a candidate row (§4). The *legal-transition rules* live in
/// the `lifecycle` module (next unit); this enum is the data they move through.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LifecycleState {
    /// A fresh observation (a KILL/Inconclusive the search surfaced).
    Surfaced,
    /// Triaged: dedup'd and cluster-suggested, awaiting a human disposition.
    Triaged,
    /// Rejected/denied at admission — terminal, kept as coverage, never a pass.
    RejectedAtAdmission,
    /// A human triage verdict: not a real finding.
    Rejected { reason: RejectReason },
    /// Merged into another candidate key / cluster.
    Duplicate,
    /// A known, accepted residual (e.g. the Aegloss unauthenticated-ingest race).
    AcceptedResidual,
    /// The human ratified the invariant — this is now a Finding.
    Ratified,
    /// A seeded failing fixture exists (a promotion precondition).
    Fixtured,
    /// The fix was applied.
    Fixed,
    /// Fixed and re-run flips KILL→DEFENDED — now a permanent regression fighter.
    /// (The spec's "Defended(regression)"; named `Regression` to avoid confusion
    /// with [`VerdictClass::Defended`], which is a probe outcome, not a lifecycle
    /// state.)
    Regression,
}

impl LifecycleState {
    /// The initial state of a candidate that ran.
    pub fn initial() -> Self {
        LifecycleState::Surfaced
    }

    /// Whether this is a terminal state — no further transition is legal.
    /// (Enforced by the `lifecycle` module; exposed here for convenience.)
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            LifecycleState::RejectedAtAdmission
                | LifecycleState::Rejected { .. }
                | LifecycleState::Duplicate
                | LifecycleState::AcceptedResidual
                | LifecycleState::Regression
        )
    }
}

/// One recorded lifecycle transition — a human decision, with who/when/why (§4).
/// Every state change appends one of these; the current [`LifecycleState`] is the
/// `to` of the last transition.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Transition {
    pub to: LifecycleState,
    /// The actor who made the decision (a person, or `"system"` for the mechanical
    /// dedup/occurrence update that is the one non-human change).
    pub actor: String,
    pub at_unix: u64,
    pub rationale: String,
}

impl Transition {
    pub fn new(
        to: LifecycleState,
        actor: impl Into<String>,
        at_unix: u64,
        rationale: impl Into<String>,
    ) -> Self {
        Transition {
            to,
            actor: actor.into(),
            at_unix,
            rationale: rationale.into(),
        }
    }
}

/// The disposition of a candidate: its current lifecycle state plus the transition
/// history that led there. The history is append-only; the current state is
/// `history.last().to`, or `Surfaced` when empty.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct Disposition {
    pub history: Vec<Transition>,
}

impl Disposition {
    /// A freshly-surfaced disposition with no transitions yet.
    pub fn surfaced() -> Self {
        Disposition { history: Vec::new() }
    }

    /// The current state (the last transition's target, or `Surfaced`).
    pub fn current(&self) -> LifecycleState {
        self.history
            .last()
            .map(|t| t.to.clone())
            .unwrap_or(LifecycleState::Surfaced)
    }
}

/// One ledger row: a distinct candidate, keyed by its canonical key.
///
/// Dedup is by `candidate_key`; a re-surfaced candidate increments `occurrence_count`
/// and refreshes `last_seen`/`bundle_ref`, and records its provenance under
/// `provenance_variants` — it never creates a second row. (The dedup logic lives in
/// the `ledger` module.)
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CandidateRecord {
    pub candidate_key: CandidateKey,
    /// Rendered template handle, `"fighter/technique"`.
    pub template: String,
    /// The registered target tool/param handle the probe exercises.
    pub target_handle: String,
    /// Rendered effect class (`Authority`): `"read-only"` / `"mutating"`.
    pub effect_class: String,
    /// Rendered oracle binding, `"kind/id/version"`.
    pub oracle: String,
    /// The mechanism identity (template, mutator, transform) the registered clustering
    /// predicate groups on (§7). Ingest-populated; defaults to template-only.
    #[serde(default)]
    pub mechanism: MechanismId,
    /// The oracle-versioned evidence-signature equivalence key (§7): the normalized shape
    /// of the recorded decisions, so two encodings of one fault share it while a distinct
    /// fault does not. Ingest-populated; empty until then, and an empty signature never
    /// clusters (default-to-separate).
    #[serde(default)]
    pub evidence_signature: String,
    pub admission: AdmissionOutcome,
    /// The probe's outcome, read from the bundle. `None` for a candidate that never
    /// ran (rejected/denied at admission).
    pub verdict: Option<VerdictClass>,
    pub evidence_fidelity: EvidenceFidelity,
    /// Handle to the pinned, offline-verifiable bundle. `None` until the candidate has
    /// a run bundle (e.g. rejected-at-admission).
    pub bundle_ref: Option<BundleRef>,
    pub provenance_variants: Vec<ProvenanceRecord>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub occurrence_count: u64,
    pub cluster_id: Option<ClusterId>,
    pub disposition: Disposition,
}

impl CandidateRecord {
    /// A minimal freshly-surfaced record (before any ingest projection fills the
    /// mirrored fields from a real `Candidate`). Occurrence starts at 1; `mechanism`
    /// carries the template only and `evidence_signature` is empty until ingest fills
    /// them (so a pre-ingest record never clusters).
    #[allow(clippy::too_many_arguments)]
    pub fn surfaced(
        candidate_key: CandidateKey,
        template: impl Into<String>,
        target_handle: impl Into<String>,
        effect_class: impl Into<String>,
        oracle: impl Into<String>,
        admission: AdmissionOutcome,
        verdict: Option<VerdictClass>,
        evidence_fidelity: EvidenceFidelity,
        now_unix: u64,
    ) -> Self {
        let template = template.into();
        CandidateRecord {
            candidate_key,
            mechanism: MechanismId::from_template(template.clone()),
            template,
            target_handle: target_handle.into(),
            effect_class: effect_class.into(),
            oracle: oracle.into(),
            evidence_signature: String::new(),
            admission,
            verdict,
            evidence_fidelity,
            bundle_ref: None,
            provenance_variants: Vec::new(),
            first_seen: now_unix,
            last_seen: now_unix,
            occurrence_count: 1,
            cluster_id: None,
            disposition: Disposition::surfaced(),
        }
    }

    /// The current lifecycle state (convenience over `self.disposition.current()`).
    pub fn state(&self) -> LifecycleState {
        self.disposition.current()
    }

    /// Whether this candidate is eligible, in principle, to become a finding: it ran,
    /// produced a promotable `Kill`, and is not exploratory-capped. (The *lifecycle*
    /// still requires a ratified invariant + a seeded fixture + a KILL→DEFENDED
    /// bundle pair before `Regression`; that gate lives in the `lifecycle` module.)
    pub fn is_promotable(&self) -> bool {
        !self.admission.is_exploratory()
            && matches!(self.verdict, Some(v) if v.is_promotable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CandidateRecord {
        CandidateRecord::surfaced(
            CandidateKey("tmpl=taint-launder/encoding-equiv;params={recipient=s:ATTACKER-IBAN-12345};target=send_money.recipient;effect=mutating;oracle=differential/f-b-taint-oracle/v1".into()),
            "taint-launder/encoding-equiv",
            "send_money.recipient",
            "mutating",
            "differential/f-b-taint-oracle/v1",
            AdmissionOutcome::Admitted {
                region: "encodings".into(),
                adequacy_target: 8,
                exploratory: false,
            },
            Some(VerdictClass::Kill),
            EvidenceFidelity::ResponseOnly,
            1_700_000_000,
        )
    }

    #[test]
    fn record_round_trips_json() {
        let r = sample();
        let json = serde_json::to_string(&r).expect("serialize");
        let back: CandidateRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(r, back);
    }

    #[test]
    fn fresh_record_is_surfaced_with_one_occurrence() {
        let r = sample();
        assert_eq!(r.state(), LifecycleState::Surfaced);
        assert_eq!(r.occurrence_count, 1);
        assert_eq!(r.first_seen, r.last_seen);
        assert!(r.disposition.history.is_empty());
    }

    #[test]
    fn a_fresh_record_carries_template_only_mechanism_and_no_signature() {
        // Until ingest fills them, a record cannot cluster (empty signature = unproven).
        let r = sample();
        assert_eq!(r.mechanism, MechanismId::from_template("taint-launder/encoding-equiv"));
        assert!(r.mechanism.mutator.is_empty() && r.mechanism.transform.is_empty());
        assert!(r.evidence_signature.is_empty());
    }

    #[test]
    fn a_pre_mechanism_ledger_line_still_loads() {
        // A line written before the mechanism/signature fields existed must deserialize
        // (the fields are `#[serde(default)]`).
        let line = r#"{"candidate_key":"k","template":"f/t","target_handle":"tool.p","effect_class":"mutating","oracle":"differential/o/v1","admission":{"outcome":"admitted","region":"r","adequacy_target":8,"exploratory":false},"verdict":"kill","evidence_fidelity":"response_only","bundle_ref":null,"provenance_variants":[],"first_seen":1,"last_seen":1,"occurrence_count":1,"cluster_id":null,"disposition":{"history":[]}}"#;
        let r: CandidateRecord = serde_json::from_str(line).expect("old line loads");
        assert_eq!(r.mechanism, MechanismId::default());
        assert!(r.evidence_signature.is_empty());
    }

    #[test]
    fn a_kill_that_is_not_exploratory_is_promotable() {
        let r = sample();
        assert!(r.is_promotable());
    }

    #[test]
    fn an_exploratory_kill_is_not_promotable() {
        // N7: an unregistered-handle candidate is capped — never a finding, even on a Kill.
        let mut r = sample();
        r.admission = AdmissionOutcome::Admitted {
            region: "encodings".into(),
            adequacy_target: 8,
            exploratory: true,
        };
        assert!(!r.is_promotable());
    }

    #[test]
    fn a_defended_outcome_is_recorded_but_not_promotable() {
        // Coverage fact, not a finding (the Owly lesson): Defended is kept, never promoted.
        let mut r = sample();
        r.verdict = Some(VerdictClass::Defended);
        assert!(!r.is_promotable());
        // and it still round-trips (coverage is recorded, not dropped).
        let json = serde_json::to_string(&r).expect("serialize");
        assert!(json.contains("defended"));
    }

    #[test]
    fn rejected_at_admission_has_no_verdict_and_is_coverage() {
        let r = CandidateRecord::surfaced(
            CandidateKey("k".into()),
            "f/t",
            "tool.param",
            "mutating",
            "differential/o/v1",
            AdmissionOutcome::Rejected { reason: "param out of bounds".into() },
            None,
            EvidenceFidelity::Inconclusive,
            1_700_000_000,
        );
        assert!(!r.admission.was_admitted());
        assert!(r.verdict.is_none());
        assert!(!r.is_promotable());
    }

    #[test]
    fn disposition_current_follows_the_last_transition() {
        let mut d = Disposition::surfaced();
        assert_eq!(d.current(), LifecycleState::Surfaced);
        d.history.push(Transition::new(
            LifecycleState::Triaged,
            "jarmo",
            1_700_000_100,
            "clustered with the url-token finding",
        ));
        d.history.push(Transition::new(
            LifecycleState::Ratified,
            "jarmo",
            1_700_000_200,
            "invariant holds: no credential in a mutating URL",
        ));
        assert_eq!(d.current(), LifecycleState::Ratified);
    }

    #[test]
    fn terminal_states_are_marked() {
        assert!(LifecycleState::Regression.is_terminal());
        assert!(LifecycleState::Duplicate.is_terminal());
        assert!(LifecycleState::Rejected { reason: RejectReason::ByDesign }.is_terminal());
        assert!(LifecycleState::RejectedAtAdmission.is_terminal());
        assert!(LifecycleState::AcceptedResidual.is_terminal());
        assert!(!LifecycleState::Surfaced.is_terminal());
        assert!(!LifecycleState::Ratified.is_terminal());
        assert!(!LifecycleState::Fixtured.is_terminal());
    }

    #[test]
    fn verdict_class_serializes_snake_case() {
        assert_eq!(serde_json::to_string(&VerdictClass::Kill).unwrap(), "\"kill\"");
        assert_eq!(
            serde_json::to_string(&VerdictClass::Inconclusive).unwrap(),
            "\"inconclusive\""
        );
    }
}
