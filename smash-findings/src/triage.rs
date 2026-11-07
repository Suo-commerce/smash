//! Triage — the pending-ratification queue (§9).
//!
//! This is the human's worklist: the promotable candidates awaiting a decision, each
//! grouped into a suggested cluster and ranked by a **transparent, recomputable**
//! score. The score is advisory ordering only — it never gates; the human still
//! decides every disposition.
//!
//! `score = severity × novelty × confidence`
//! - **severity** — the invariant's declared impact, looked up by technique handle
//!   (decision 4). It is *not* a candidate field; an untrusted proposer must never rank
//!   its own output. The core takes any [`SeveritySource`]; the engine-registry-backed
//!   source lands when the technique metadata gains a severity field (per the admission
//!   gap audit, that field is not built yet — [`SeverityMap`] is the usable source now).
//! - **novelty** — a candidate whose suggested cluster nobody has dispositioned yet is
//!   novel; one in an already-acted-on cluster is less so. (Ratify a *cause* once.)
//! - **confidence** — `evidence_fidelity`: a receipt-confirmed `Kill` outranks one
//!   inferred from a response code (the Aegloss fidelity lesson).
//!
//! Only promotable candidates (a non-exploratory `Kill`) that are still pre-disposition
//! (`Surfaced`/`Triaged`) enter the queue. A `Defended`/`Inconclusive`/exploratory
//! candidate is coverage, not a ratification candidate, and never appears here.

use crate::ledger::Ledger;
use crate::record::{
    CandidateKey, CandidateRecord, EvidenceFidelity, LifecycleState,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

// ── Severity (looked up by handle; never a candidate field) ──────────────────

/// The declared impact of an invariant/technique. Weighted for ranking.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn weight(self) -> u32 {
        match self {
            Severity::Low => 1,
            Severity::Medium => 3,
            Severity::High => 7,
            Severity::Critical => 15,
        }
    }
}

/// Where severity comes from — keyed by technique handle (`"fighter/technique"`). The
/// core takes any implementor; a registry-backed one is a later, feature-gated add.
pub trait SeveritySource {
    fn severity(&self, technique: &str) -> Severity;
}

/// A simple map-backed severity source with a default for unknown handles.
#[derive(Clone, Debug)]
pub struct SeverityMap {
    map: BTreeMap<String, Severity>,
    default: Severity,
}

impl SeverityMap {
    pub fn new(default: Severity) -> Self {
        SeverityMap {
            map: BTreeMap::new(),
            default,
        }
    }

    pub fn with(mut self, technique: impl Into<String>, severity: Severity) -> Self {
        self.map.insert(technique.into(), severity);
        self
    }
}

impl SeveritySource for SeverityMap {
    fn severity(&self, technique: &str) -> Severity {
        self.map.get(technique).copied().unwrap_or(self.default)
    }
}

// ── Scoring factors ──────────────────────────────────────────────────────────

fn confidence_weight(f: EvidenceFidelity) -> u32 {
    match f {
        EvidenceFidelity::EffectConfirmed => 4,
        EvidenceFidelity::ResponseOnly => 2,
        EvidenceFidelity::Inconclusive => 1,
    }
}

fn novelty_weight(novel: bool) -> u32 {
    if novel {
        3
    } else {
        1
    }
}

/// The suggested-cluster signal: shared template + oracle + region (same mechanism,
/// same invariant, same region of its space). Advisory — the human owns the real
/// cluster boundaries and the ledger never auto-merges (§3).
pub fn suggested_cluster(record: &CandidateRecord) -> String {
    let region = match &record.admission {
        crate::record::AdmissionOutcome::Admitted { region, .. } => region.as_str(),
        _ => "-",
    };
    format!("{}|{}|{}", record.template, record.oracle, region)
}

/// Whether a record has left the pending stage (anyone has dispositioned it).
fn is_dispositioned(state: &LifecycleState) -> bool {
    !matches!(state, LifecycleState::Surfaced | LifecycleState::Triaged)
}

// ── Next action (the triage hint) ────────────────────────────────────────────

/// What the human does next with a candidate, given its state and promotability.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextAction {
    /// Promotable, freshly surfaced — triage it (cluster + confirm).
    Triage,
    /// Triaged and promotable — ratify the invariant (makes it a finding).
    RatifyInvariant,
    /// Ratified — seed the failing fixture (a promotion precondition).
    SeedFixture,
    /// Fixtured — apply the fix.
    ApplyFix,
    /// Fixed — promote to regression with the KILL→DEFENDED bundle pair.
    PromoteWithProof,
    /// Ran, but cannot become a finding (Defended / Inconclusive / exploratory).
    NotPromotable,
    /// Terminal — nothing to do.
    Done,
}

/// The next action for a single record.
pub fn next_action(record: &CandidateRecord) -> NextAction {
    let state = record.state();
    if state.is_terminal() {
        return NextAction::Done;
    }
    match state {
        LifecycleState::Surfaced => {
            if record.is_promotable() {
                NextAction::Triage
            } else {
                NextAction::NotPromotable
            }
        }
        LifecycleState::Triaged => {
            if record.is_promotable() {
                NextAction::RatifyInvariant
            } else {
                NextAction::NotPromotable
            }
        }
        LifecycleState::Ratified => NextAction::SeedFixture,
        LifecycleState::Fixtured => NextAction::ApplyFix,
        LifecycleState::Fixed => NextAction::PromoteWithProof,
        // terminal states handled above
        _ => NextAction::Done,
    }
}

// ── The report ───────────────────────────────────────────────────────────────

/// One entry in the ranked pending queue.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TriageEntry {
    pub candidate_key: CandidateKey,
    pub suggested_cluster: String,
    pub severity: Severity,
    pub novel_cluster: bool,
    pub fidelity: EvidenceFidelity,
    pub occurrence_count: u64,
    pub state: LifecycleState,
    pub next_action: NextAction,
    /// The advisory ordering score: `severity.weight × novelty × confidence`.
    pub score: u32,
}

/// A suggested-cluster summary: how many pending candidates share it, its top score,
/// and whether anyone has acted on the cause yet.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ClusterSummary {
    pub cluster: String,
    pub count: usize,
    pub top_score: u32,
    pub novel: bool,
}

/// The triage report: the ranked pending queue plus the cluster summaries.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TriageReport {
    pub entries: Vec<TriageEntry>,
    pub clusters: Vec<ClusterSummary>,
}

/// Build the triage report from the ledger. Selects the promotable, pre-disposition
/// candidates, suggests clusters, computes novelty against the whole ledger, ranks by
/// score (desc, then by key for determinism), and summarizes the clusters.
pub fn triage(ledger: &Ledger, severity: &dyn SeveritySource) -> TriageReport {
    // A cluster is novel iff no record in it has been dispositioned yet.
    let mut handled_clusters: BTreeSet<String> = BTreeSet::new();
    for r in ledger.iter() {
        if is_dispositioned(&r.state()) {
            handled_clusters.insert(suggested_cluster(r));
        }
    }

    let mut entries: Vec<TriageEntry> = Vec::new();
    for r in ledger.iter() {
        // Pending-ratification queue: promotable + still pre-disposition.
        if !r.is_promotable() {
            continue;
        }
        let state = r.state();
        if !matches!(state, LifecycleState::Surfaced | LifecycleState::Triaged) {
            continue;
        }

        let cluster = suggested_cluster(r);
        let novel = !handled_clusters.contains(&cluster);
        let sev = severity.severity(&r.template);
        let score =
            sev.weight() * novelty_weight(novel) * confidence_weight(r.evidence_fidelity);

        entries.push(TriageEntry {
            candidate_key: r.candidate_key.clone(),
            suggested_cluster: cluster,
            severity: sev,
            novel_cluster: novel,
            fidelity: r.evidence_fidelity,
            occurrence_count: r.occurrence_count,
            state,
            next_action: next_action(r),
            score,
        });
    }

    // Rank: score desc, then candidate key asc (deterministic).
    entries.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.candidate_key.cmp(&b.candidate_key))
    });

    // Cluster summaries from the pending entries.
    let mut by_cluster: BTreeMap<String, ClusterSummary> = BTreeMap::new();
    for e in &entries {
        let cs = by_cluster
            .entry(e.suggested_cluster.clone())
            .or_insert_with(|| ClusterSummary {
                cluster: e.suggested_cluster.clone(),
                count: 0,
                top_score: 0,
                novel: e.novel_cluster,
            });
        cs.count += 1;
        cs.top_score = cs.top_score.max(e.score);
    }
    let mut clusters: Vec<ClusterSummary> = by_cluster.into_values().collect();
    clusters.sort_by(|a, b| b.top_score.cmp(&a.top_score).then_with(|| a.cluster.cmp(&b.cluster)));

    TriageReport { entries, clusters }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::apply_transition;
    use crate::record::{
        AdmissionOutcome, CandidateKey, CandidateRecord, EvidenceFidelity, LifecycleState,
        RejectReason, VerdictClass,
    };

    fn rec(
        key: &str,
        template: &str,
        region: &str,
        verdict: VerdictClass,
        fidelity: EvidenceFidelity,
        exploratory: bool,
    ) -> CandidateRecord {
        CandidateRecord::surfaced(
            CandidateKey(key.into()),
            template,
            "send_money.recipient",
            "mutating",
            "differential/f-b-taint-oracle/v1",
            AdmissionOutcome::Admitted {
                region: region.into(),
                adequacy_target: 8,
                exploratory,
            },
            Some(verdict),
            fidelity,
            1_700_000_000,
        )
    }

    fn sev_source() -> SeverityMap {
        SeverityMap::new(Severity::Medium)
            .with("taint-launder/encoding-equiv", Severity::Critical)
            .with("mcp/input-shape", Severity::Low)
    }

    #[test]
    fn queue_ranks_critical_novel_confirmed_above_low_known_responseonly() {
        let mut l = Ledger::new();
        l.upsert(rec("k-hi", "taint-launder/encoding-equiv", "r1", VerdictClass::Kill, EvidenceFidelity::EffectConfirmed, false));
        l.upsert(rec("k-lo", "mcp/input-shape", "r2", VerdictClass::Kill, EvidenceFidelity::ResponseOnly, false));
        let report = triage(&l, &sev_source());
        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.entries[0].candidate_key, CandidateKey("k-hi".into()), "critical+confirmed ranks first");
        // critical(15) * novel(3) * confirmed(4) = 180 ; low(1)*novel(3)*response(2) = 6
        assert_eq!(report.entries[0].score, 180);
        assert_eq!(report.entries[1].score, 6);
    }

    #[test]
    fn non_promotable_candidates_are_excluded() {
        let mut l = Ledger::new();
        l.upsert(rec("defended", "taint-launder/encoding-equiv", "r1", VerdictClass::Defended, EvidenceFidelity::ResponseOnly, false));
        l.upsert(rec("inconclusive", "taint-launder/encoding-equiv", "r1", VerdictClass::Inconclusive, EvidenceFidelity::Inconclusive, false));
        l.upsert(rec("exploratory", "taint-launder/encoding-equiv", "r1", VerdictClass::Kill, EvidenceFidelity::ResponseOnly, true));
        let report = triage(&l, &sev_source());
        assert!(report.entries.is_empty(), "no promotable pending candidates");
    }

    #[test]
    fn a_dispositioned_sibling_makes_the_cluster_not_novel() {
        let mut l = Ledger::new();
        // one in the cluster already ratified → cluster handled
        let mut done = rec("ratified", "taint-launder/encoding-equiv", "r1", VerdictClass::Kill, EvidenceFidelity::EffectConfirmed, false);
        apply_transition(&mut done, LifecycleState::Triaged, "jarmo", 1, "t").unwrap();
        apply_transition(&mut done, LifecycleState::Ratified, "jarmo", 2, "r").unwrap();
        l.upsert(done);
        // a fresh sibling in the SAME cluster (same template+oracle+region)
        l.upsert(rec("fresh", "taint-launder/encoding-equiv", "r1", VerdictClass::Kill, EvidenceFidelity::EffectConfirmed, false));

        let report = triage(&l, &sev_source());
        assert_eq!(report.entries.len(), 1, "only the fresh one is pending");
        assert!(!report.entries[0].novel_cluster, "cluster already acted on → not novel");
        // critical(15) * known(1) * confirmed(4) = 60 (vs 180 if it were novel)
        assert_eq!(report.entries[0].score, 60);
    }

    #[test]
    fn clusters_group_by_template_oracle_region() {
        let mut l = Ledger::new();
        l.upsert(rec("a", "taint-launder/encoding-equiv", "r1", VerdictClass::Kill, EvidenceFidelity::ResponseOnly, false));
        l.upsert(rec("b", "taint-launder/encoding-equiv", "r1", VerdictClass::Kill, EvidenceFidelity::ResponseOnly, false));
        l.upsert(rec("c", "taint-launder/encoding-equiv", "r2", VerdictClass::Kill, EvidenceFidelity::ResponseOnly, false));
        let report = triage(&l, &sev_source());
        // r1 cluster has 2, r2 cluster has 1.
        let r1 = report.clusters.iter().find(|c| c.cluster.ends_with("|r1")).unwrap();
        let r2 = report.clusters.iter().find(|c| c.cluster.ends_with("|r2")).unwrap();
        assert_eq!(r1.count, 2);
        assert_eq!(r2.count, 1);
    }

    #[test]
    fn next_action_walks_the_lifecycle() {
        let mut r = rec("k", "taint-launder/encoding-equiv", "r1", VerdictClass::Kill, EvidenceFidelity::EffectConfirmed, false);
        assert_eq!(next_action(&r), NextAction::Triage);
        apply_transition(&mut r, LifecycleState::Triaged, "j", 1, "t").unwrap();
        assert_eq!(next_action(&r), NextAction::RatifyInvariant);
        apply_transition(&mut r, LifecycleState::Ratified, "j", 2, "r").unwrap();
        assert_eq!(next_action(&r), NextAction::SeedFixture);
        apply_transition(&mut r, LifecycleState::Fixtured, "j", 3, "f").unwrap();
        assert_eq!(next_action(&r), NextAction::ApplyFix);
        apply_transition(&mut r, LifecycleState::Fixed, "j", 4, "x").unwrap();
        assert_eq!(next_action(&r), NextAction::PromoteWithProof);
    }

    #[test]
    fn next_action_flags_non_promotable_and_terminal() {
        let defended = rec("d", "taint-launder/encoding-equiv", "r1", VerdictClass::Defended, EvidenceFidelity::ResponseOnly, false);
        assert_eq!(next_action(&defended), NextAction::NotPromotable);

        let mut residual = rec("res", "taint-launder/encoding-equiv", "r1", VerdictClass::Kill, EvidenceFidelity::EffectConfirmed, false);
        apply_transition(&mut residual, LifecycleState::Triaged, "j", 1, "t").unwrap();
        apply_transition(&mut residual, LifecycleState::AcceptedResidual, "j", 2, "accepted").unwrap();
        assert_eq!(next_action(&residual), NextAction::Done);
    }

    #[test]
    fn report_round_trips_json() {
        let mut l = Ledger::new();
        l.upsert(rec("a", "taint-launder/encoding-equiv", "r1", VerdictClass::Kill, EvidenceFidelity::ResponseOnly, false));
        let report = triage(&l, &sev_source());
        let json = serde_json::to_string(&report).unwrap();
        let back: TriageReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn severity_map_defaults_unknown_handles() {
        let s = sev_source();
        assert_eq!(s.severity("taint-launder/encoding-equiv"), Severity::Critical);
        assert_eq!(s.severity("unknown/handle"), Severity::Medium);
    }

    #[test]
    fn a_rejected_cluster_sibling_also_marks_handled() {
        // Someone looked at this cause (rejected it as by-design) → not novel for a fresh sibling.
        let mut l = Ledger::new();
        let mut rej = rec("rej", "taint-launder/encoding-equiv", "r1", VerdictClass::Kill, EvidenceFidelity::ResponseOnly, false);
        apply_transition(&mut rej, LifecycleState::Triaged, "j", 1, "t").unwrap();
        apply_transition(&mut rej, LifecycleState::Rejected { reason: RejectReason::ByDesign }, "j", 2, "by design").unwrap();
        l.upsert(rej);
        l.upsert(rec("fresh", "taint-launder/encoding-equiv", "r1", VerdictClass::Kill, EvidenceFidelity::ResponseOnly, false));
        let report = triage(&l, &sev_source());
        assert_eq!(report.entries.len(), 1);
        assert!(!report.entries[0].novel_cluster);
    }
}
