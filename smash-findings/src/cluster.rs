//! The registered deterministic clustering predicate + retention
//! (autonomous-loop §7 and §5.2). Findings-management build-order item 4.
//!
//! Distinct from triage's loose **suggestion** (`triage::suggested_cluster`,
//! findings §3 = template|oracle|region): this is the *registered, versioned* predicate
//! the run report / capstone use to group N near-duplicate encodings of **one** fault
//! into **one** cluster, reproducibly. The rule (§7):
//!
//! > Two findings cluster iff identical **mechanism id** `(template, mutator, transform)`
//! > **and** matching **evidence signature**. Default-to-separate: an unproven (empty)
//! > signature never merges. Never across templates (the template is part of the
//! > mechanism). **Matching verdicts alone never cluster** — the signature, not the
//! > verdict, decides.
//!
//! It stays a *suggestion*: the human still owns the final cluster boundaries
//! (findings §3 / §10.3). The predicate never auto-promotes and never merges distinct
//! causes — it only makes the grouping reproducible and precise. The §7 guards are kept:
//! the instance count is never reduced (it sums `occurrence_count`), a cluster over the
//! review cap is flagged to escalate as its own item, and each cluster names the members
//! its representative stands for.
//!
//! Retention (§5.2): a **full bundle** is kept for every `Kill` instance and every
//! cluster representative; everything else keeps a **typed summary row** only. The plan's
//! `summary_only` list is the marker that *names its omissions* — a reduced export that
//! cannot enumerate what it dropped is a verification failure (§8).

use crate::ledger::Ledger;
use crate::record::{CandidateKey, MechanismId, VerdictClass};
use std::collections::{BTreeMap, BTreeSet};

/// Bump when the predicate's rule changes, so a historical cluster assignment is
/// explainable rather than silently shifting (the mirror of `candidate_key`'s version).
pub const CLUSTER_PREDICATE_VERSION: u32 = 1;

type ClusterGroups = BTreeMap<(ClusterKey, Option<CandidateKey>), Vec<(CandidateKey, u64)>>;

/// The registered cluster key: mechanism id + evidence signature. Equality here *is* the
/// predicate.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ClusterKey {
    pub mechanism: MechanismId,
    pub evidence_signature: String,
}

/// One cluster: its key, the deterministic representative, the members it stands for, and
/// the total instance count (never reduced — §7).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Cluster {
    pub key: ClusterKey,
    /// The representative member — the lowest candidate key in the cluster (deterministic).
    /// Never trimmed from retention.
    pub representative: CandidateKey,
    /// Every candidate key this cluster stands for, in key order.
    pub members: Vec<CandidateKey>,
    /// Sum of the members' occurrence counts — the number of instances, never reduced.
    pub instance_count: u64,
    /// `true` when the cluster exceeds the review cap and must escalate as its own item.
    pub over_cap: bool,
}

/// The clustering of a ledger's promotable findings under the registered predicate.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClusterReport {
    pub predicate_version: u32,
    pub clusters: Vec<Cluster>,
}

/// Cluster the ledger's promotable findings (non-exploratory `Kill`s) under the §7
/// predicate. `instance_cap` is the per-cluster review cap: a cluster with more members
/// than this is flagged `over_cap` to escalate. Non-promotable rows (Defended /
/// Inconclusive / exploratory) are coverage, not findings, and never enter a cluster.
///
/// Deterministic: groups iterate the ledger in key order, members are key-sorted, the
/// representative is the lowest key, and clusters are ordered by `(key, representative)`.
pub fn cluster_findings(ledger: &Ledger, instance_cap: usize) -> ClusterReport {
    // Group by the cluster key. An empty (unproven) signature must never merge, so such a
    // finding is disambiguated by its own candidate key — it clusters only with itself.
    let mut groups = ClusterGroups::new();
    for r in ledger.iter() {
        if !r.is_promotable() {
            continue;
        }
        let key = ClusterKey {
            mechanism: r.mechanism.clone(),
            evidence_signature: r.evidence_signature.clone(),
        };
        let disambig = if r.evidence_signature.is_empty() {
            Some(r.candidate_key.clone())
        } else {
            None
        };
        groups
            .entry((key, disambig))
            .or_default()
            .push((r.candidate_key.clone(), r.occurrence_count));
    }

    let mut clusters: Vec<Cluster> = groups
        .into_iter()
        .map(|((key, _), mut members_with_counts)| {
            members_with_counts.sort_by(|a, b| a.0.cmp(&b.0));
            let instance_count = members_with_counts.iter().map(|(_, n)| *n).sum();
            let members: Vec<CandidateKey> =
                members_with_counts.into_iter().map(|(k, _)| k).collect();
            let representative = members[0].clone();
            let over_cap = members.len() > instance_cap;
            Cluster { key, representative, members, instance_count, over_cap }
        })
        .collect();
    clusters.sort_by(|a, b| a.key.cmp(&b.key).then_with(|| a.representative.cmp(&b.representative)));

    ClusterReport { predicate_version: CLUSTER_PREDICATE_VERSION, clusters }
}

/// The retention plan (§5.2): a full bundle for every `Kill` instance and every cluster
/// representative; a typed summary row for everything else.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RetentionPlan {
    /// Keys whose full bundle is retained (every `Kill`, plus every representative).
    pub full: Vec<CandidateKey>,
    /// Keys kept as a typed summary row only — the marker that **names its omissions**.
    pub summary_only: Vec<CandidateKey>,
}

/// Build the retention plan from the ledger and a clustering. Representatives are never
/// trimmed; a `Kill` is always kept in full; a non-`Kill` coverage row is summary-only.
pub fn retention_plan(ledger: &Ledger, clusters: &ClusterReport) -> RetentionPlan {
    let reps: BTreeSet<&CandidateKey> =
        clusters.clusters.iter().map(|c| &c.representative).collect();
    let mut full = Vec::new();
    let mut summary_only = Vec::new();
    for r in ledger.iter() {
        let is_kill = matches!(r.verdict, Some(VerdictClass::Kill));
        if is_kill || reps.contains(&r.candidate_key) {
            full.push(r.candidate_key.clone());
        } else {
            summary_only.push(r.candidate_key.clone());
        }
    }
    RetentionPlan { full, summary_only }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{
        AdmissionOutcome, CandidateKey, CandidateRecord, EvidenceFidelity, MechanismId, VerdictClass,
    };

    /// A promotable finding with an explicit mechanism + evidence signature + occurrence.
    fn finding(key: &str, mutator: &str, sig: &str, occ: u64) -> CandidateRecord {
        rec(key, "taint-launder/encoding-equiv", mutator, sig, VerdictClass::Kill, false, occ)
    }

    fn rec(
        key: &str,
        template: &str,
        mutator: &str,
        sig: &str,
        verdict: VerdictClass,
        exploratory: bool,
        occ: u64,
    ) -> CandidateRecord {
        let mut r = CandidateRecord::surfaced(
            CandidateKey(key.into()),
            template,
            "send_money.recipient",
            "mutating",
            "differential/f-b-taint-oracle/v1",
            AdmissionOutcome::Admitted {
                region: "encodings".into(),
                adequacy_target: 8,
                exploratory,
            },
            Some(verdict),
            EvidenceFidelity::ResponseOnly,
            1,
        );
        r.mechanism = MechanismId {
            template: template.into(),
            mutator: mutator.into(),
            transform: mutator.into(),
        };
        r.evidence_signature = sig.into();
        r.occurrence_count = occ;
        r
    }

    fn ledger(records: Vec<CandidateRecord>) -> Ledger {
        let mut l = Ledger::new();
        for r in records {
            l.upsert(r);
        }
        l
    }

    #[test]
    fn same_mechanism_and_signature_cluster_into_one() {
        // N encodings of one fault: same mutator + same evidence signature → one cluster.
        let l = ledger(vec![
            finding("dash", "encoding-equiv", "sig-w1", 3),
            finding("unicode", "encoding-equiv", "sig-w1", 2),
        ]);
        let report = cluster_findings(&l, 100);
        assert_eq!(report.clusters.len(), 1, "one fault → one cluster");
        let c = &report.clusters[0];
        assert_eq!(c.representative, CandidateKey("dash".into()), "lowest key is representative");
        assert_eq!(c.members.len(), 2);
        assert_eq!(c.instance_count, 5, "occurrence counts sum, never reduced");
        assert!(!c.over_cap);
    }

    #[test]
    fn same_mechanism_different_signature_are_two_clusters() {
        // Acceptance 8: adjacent-but-distinct faults (same mechanism, different evidence
        // signature) must stay separate — matching verdicts alone never cluster.
        let l = ledger(vec![
            finding("a", "encoding-equiv", "sig-w1", 1),
            finding("b", "encoding-equiv", "sig-other", 1),
        ]);
        assert_eq!(cluster_findings(&l, 100).clusters.len(), 2);
    }

    #[test]
    fn different_templates_never_merge() {
        // The template is part of the mechanism, so a different template can never cluster
        // with another even on an identical signature.
        let l = ledger(vec![
            rec("w1", "taint-launder/encoding-equiv", "encoding-equiv", "sig", VerdictClass::Kill, false, 1),
            rec("w2", "sensitive-field-selection/field-key", "field-key", "sig", VerdictClass::Kill, false, 1),
        ]);
        assert_eq!(cluster_findings(&l, 100).clusters.len(), 2, "never merge across templates");
    }

    #[test]
    fn an_empty_signature_never_merges() {
        // Default-to-separate: two findings with identical mechanism but no proven
        // signature are each their own singleton.
        let l = ledger(vec![
            finding("a", "encoding-equiv", "", 1),
            finding("b", "encoding-equiv", "", 1),
        ]);
        let report = cluster_findings(&l, 100);
        assert_eq!(report.clusters.len(), 2, "unproven equivalence does not cluster");
        assert!(report.clusters.iter().all(|c| c.members.len() == 1));
    }

    #[test]
    fn non_promotable_records_are_not_clustered() {
        let l = ledger(vec![
            rec("defended", "taint-launder/encoding-equiv", "encoding-equiv", "sig", VerdictClass::Defended, false, 1),
            rec("explor", "taint-launder/encoding-equiv", "encoding-equiv", "sig", VerdictClass::Kill, true, 1),
            finding("kill", "encoding-equiv", "sig", 1),
        ]);
        let report = cluster_findings(&l, 100);
        assert_eq!(report.clusters.len(), 1, "only the promotable Kill clusters");
        assert_eq!(report.clusters[0].representative, CandidateKey("kill".into()));
    }

    #[test]
    fn a_cluster_over_the_cap_is_flagged_to_escalate() {
        let l = ledger(vec![
            finding("a", "encoding-equiv", "sig", 1),
            finding("b", "encoding-equiv", "sig", 1),
            finding("c", "encoding-equiv", "sig", 1),
        ]);
        let report = cluster_findings(&l, 2); // 3 members > cap 2
        assert_eq!(report.clusters.len(), 1);
        assert!(report.clusters[0].over_cap, "a cluster over the cap escalates as its own item");
    }

    #[test]
    fn predicate_version_is_recorded() {
        let l = ledger(vec![finding("a", "encoding-equiv", "sig", 1)]);
        assert_eq!(cluster_findings(&l, 100).predicate_version, CLUSTER_PREDICATE_VERSION);
        assert_eq!(CLUSTER_PREDICATE_VERSION, 1);
    }

    #[test]
    fn retention_keeps_kills_full_and_coverage_summary_only() {
        let l = ledger(vec![
            finding("kill-a", "encoding-equiv", "sig", 1),
            rec("defended", "taint-launder/encoding-equiv", "encoding-equiv", "sig2", VerdictClass::Defended, false, 1),
        ]);
        let report = cluster_findings(&l, 100);
        let plan = retention_plan(&l, &report);
        assert!(plan.full.contains(&CandidateKey("kill-a".into())), "a Kill is kept in full");
        assert!(
            plan.summary_only.contains(&CandidateKey("defended".into())),
            "a Defended coverage row is summary-only, and named in the marker"
        );
        assert!(!plan.full.contains(&CandidateKey("defended".into())));
    }

    #[test]
    fn the_representative_is_always_retained_in_full() {
        // Even if a representative somehow weren't a Kill, §5.2 keeps it in full. (Here it
        // is a Kill, so this also confirms the Kill path.)
        let l = ledger(vec![finding("rep", "encoding-equiv", "sig", 1)]);
        let report = cluster_findings(&l, 100);
        let rep = report.clusters[0].representative.clone();
        let plan = retention_plan(&l, &report);
        assert!(plan.full.contains(&rep));
    }
}
