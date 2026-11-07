//! Coverage aggregation across packs — the ledger's second read-model (§5).
//!
//! The candidate ledger answers "what did we find?"; this answers "what did we
//! *search*?" — and keeps the two honest. A run contributes, per `(target, technique,
//! region)`, one coverage fact using the loop's two-axis model; this module stores
//! those facts across packs and rolls them up per target.
//!
//! The honest line, made structural: a region counts as covered **only** when it is
//! `sample-resolved` (Sampled *and* every attempt resolved to Pass/Fail — no
//! inconclusive, no error, not poisoned). A `Partial` region, an inconclusive, a
//! timeout, a poison — all are *gaps*, not coverage. So "complete" here means "every
//! declared region was sample-resolved," never "secure," and a zero-finding run is a
//! coverage fact, not a blank (the Owly lesson).
//!
//! The `CoverageFact` and the roll-up are pure serde data (no `smash-*` dep). Only the
//! projection from a live `smash_loop::coverage::RegionCoverage` into a `CoverageFact`
//! needs the loop, so it is behind the `ingest` feature.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

/// A region's search state (mirror of `smash_loop::coverage::SearchStatus`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Unvisited,
    Partial,
    Sampled,
}

/// The location of a coverage fact: which pack/target, which technique handle, which
/// region. The aggregation key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct CoverageKey {
    /// The pack/target label (e.g. `"storm-gate"`, `"aegloss"`, `"owly"`).
    pub target: String,
    /// The technique handle, `"fighter/technique"`.
    pub technique: String,
    /// The region within that technique's declared partition.
    pub region: String,
}

/// One region's coverage, as a run recorded it. `sample_resolved` is the only state
/// that counts as coverage; everything else is a gap with a `summary_cause`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CoverageFact {
    pub key: CoverageKey,
    pub status: CoverageStatus,
    pub sample_resolved: bool,
    /// The precedence-ranked gap cause when this region is not resolved (e.g.
    /// `"Poisoned"`, `"InadequateSample"`, `"UnresolvedVerdict"`); `None` when resolved.
    pub summary_cause: Option<String>,
    pub planner_denials: u32,
    pub throttled: bool,
    /// Dispatched-probe attempts recorded for this region, and the region's adequacy
    /// target — so a report can say "3/8 resolved". (A `RegionCoverage` does not retain
    /// these; the projecting caller supplies them.)
    pub attempts: u64,
    pub adequacy_target: u64,
}

/// Rolled-up coverage for one target across all its techniques/regions.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TargetCoverage {
    pub target: String,
    pub total_regions: usize,
    pub sample_resolved: usize,
    pub gaps: usize,
    /// Gap cause → how many regions carry it (as the summary cause).
    pub gap_causes: BTreeMap<String, u32>,
    /// `true` iff every declared region is sample-resolved. **Not** "secure" — it means
    /// "no divergence observed across the searched space," nothing more.
    pub complete: bool,
}

/// The coverage ledger: one fact per `(target, technique, region)`, latest-wins (a
/// later run's cumulative coverage supersedes an earlier one for the same cell).
#[derive(Clone, Debug, Default)]
pub struct CoverageLedger {
    facts: BTreeMap<CoverageKey, CoverageFact>,
}

impl CoverageLedger {
    pub fn new() -> Self {
        CoverageLedger::default()
    }

    pub fn len(&self) -> usize {
        self.facts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }

    pub fn get(&self, key: &CoverageKey) -> Option<&CoverageFact> {
        self.facts.get(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = &CoverageFact> {
        self.facts.values()
    }

    /// Record a coverage fact. Latest-wins per cell. Returns `true` for a new cell,
    /// `false` when an existing cell was superseded.
    pub fn upsert(&mut self, fact: CoverageFact) -> bool {
        let new = !self.facts.contains_key(&fact.key);
        self.facts.insert(fact.key.clone(), fact);
        new
    }

    /// Roll up per target, in target order. `complete` is true only when every region
    /// recorded for the target is sample-resolved.
    pub fn report(&self) -> Vec<TargetCoverage> {
        let mut by_target: BTreeMap<String, TargetCoverage> = BTreeMap::new();
        for fact in self.facts.values() {
            let tc = by_target
                .entry(fact.key.target.clone())
                .or_insert_with(|| TargetCoverage {
                    target: fact.key.target.clone(),
                    total_regions: 0,
                    sample_resolved: 0,
                    gaps: 0,
                    gap_causes: BTreeMap::new(),
                    complete: true,
                });
            tc.total_regions += 1;
            if fact.sample_resolved {
                tc.sample_resolved += 1;
            } else {
                tc.gaps += 1;
                let cause = fact.summary_cause.clone().unwrap_or_else(|| "unresolved".into());
                *tc.gap_causes.entry(cause).or_insert(0) += 1;
            }
        }
        for tc in by_target.values_mut() {
            tc.complete = tc.total_regions > 0 && tc.gaps == 0;
        }
        by_target.into_values().collect()
    }

    /// Write the coverage ledger as JSONL — one fact per line, in key order.
    pub fn write_jsonl(&self, path: &Path) -> io::Result<()> {
        let mut out = String::new();
        for fact in self.facts.values() {
            let line = serde_json::to_string(fact)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            out.push_str(&line);
            out.push('\n');
        }
        std::fs::write(path, out)
    }

    /// Read a coverage ledger from JSONL. Blank lines ignored; a malformed line is an
    /// error (fail closed).
    pub fn read_jsonl(path: &Path) -> io::Result<CoverageLedger> {
        let text = std::fs::read_to_string(path)?;
        let mut ledger = CoverageLedger::new();
        for (lineno, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let fact: CoverageFact = serde_json::from_str(line).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("coverage line {}: {e}", lineno + 1),
                )
            })?;
            ledger.facts.insert(fact.key.clone(), fact);
        }
        Ok(ledger)
    }
}

/// Project a live `smash_loop::coverage::RegionCoverage` into a [`CoverageFact`]. The
/// `RegionCoverage` does not retain the attempt count or adequacy target, so the
/// projecting caller (which has the `RegionPartition` and the dispatched outcomes)
/// supplies them.
#[cfg(feature = "ingest")]
pub fn fact_from_region(
    target: impl Into<String>,
    technique: impl Into<String>,
    region: impl Into<String>,
    cov: &smash_loop::coverage::RegionCoverage,
    attempts: u64,
    adequacy_target: u64,
) -> CoverageFact {
    use smash_loop::coverage::SearchStatus;
    let status = match cov.status {
        SearchStatus::Unvisited => CoverageStatus::Unvisited,
        SearchStatus::Partial => CoverageStatus::Partial,
        SearchStatus::Sampled => CoverageStatus::Sampled,
    };
    CoverageFact {
        key: CoverageKey {
            target: target.into(),
            technique: technique.into(),
            region: region.into(),
        },
        status,
        sample_resolved: cov.is_sample_resolved(),
        summary_cause: cov.summary_cause().map(|c| format!("{c:?}")),
        planner_denials: cov.planner_denials,
        throttled: cov.throttled,
        attempts,
        adequacy_target,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(target: &str, tech: &str, region: &str, resolved: bool, cause: Option<&str>) -> CoverageFact {
        CoverageFact {
            key: CoverageKey {
                target: target.into(),
                technique: tech.into(),
                region: region.into(),
            },
            status: if resolved { CoverageStatus::Sampled } else { CoverageStatus::Partial },
            sample_resolved: resolved,
            summary_cause: cause.map(|c| c.into()),
            planner_denials: 0,
            throttled: false,
            attempts: if resolved { 8 } else { 3 },
            adequacy_target: 8,
        }
    }

    #[test]
    fn upsert_is_latest_wins_per_cell() {
        let mut l = CoverageLedger::new();
        assert!(l.upsert(fact("aegloss", "approve/decision", "encoded-token", false, Some("InadequateSample"))));
        assert!(!l.upsert(fact("aegloss", "approve/decision", "encoded-token", true, None)), "same cell supersedes");
        assert_eq!(l.len(), 1);
        assert!(l.iter().next().unwrap().sample_resolved, "later fully-resolved fact wins");
    }

    #[test]
    fn report_rolls_up_per_target_with_gap_causes() {
        let mut l = CoverageLedger::new();
        l.upsert(fact("aegloss", "approve/decision", "r1", true, None));
        l.upsert(fact("aegloss", "approve/decision", "r2", false, Some("Poisoned")));
        l.upsert(fact("aegloss", "approve/resolve", "r3", false, Some("InadequateSample")));
        l.upsert(fact("storm-gate", "taint/encoding", "r1", true, None));

        let report = l.report();
        assert_eq!(report.len(), 2, "two targets");

        let aegloss = report.iter().find(|t| t.target == "aegloss").unwrap();
        assert_eq!(aegloss.total_regions, 3);
        assert_eq!(aegloss.sample_resolved, 1);
        assert_eq!(aegloss.gaps, 2);
        assert!(!aegloss.complete, "two gaps → not complete");
        assert_eq!(aegloss.gap_causes.get("Poisoned"), Some(&1));
        assert_eq!(aegloss.gap_causes.get("InadequateSample"), Some(&1));

        let storm = report.iter().find(|t| t.target == "storm-gate").unwrap();
        assert!(storm.complete, "all regions resolved");
        assert_eq!(storm.gaps, 0);
    }

    #[test]
    fn a_target_with_only_resolved_regions_is_complete_but_not_secure() {
        // "complete" is a coverage statement, never a security claim — it only means
        // every declared region was sample-resolved.
        let mut l = CoverageLedger::new();
        l.upsert(fact("owly", "extraction", "r1", true, None));
        l.upsert(fact("owly", "extraction", "r2", true, None));
        let report = l.report();
        let owly = &report[0];
        assert!(owly.complete);
        assert_eq!(owly.sample_resolved, 2);
        assert_eq!(owly.gaps, 0);
    }

    #[test]
    fn zero_finding_run_is_recorded_coverage_not_blank() {
        // A run that found nothing still records its searched regions as coverage.
        let mut l = CoverageLedger::new();
        l.upsert(fact("owly", "lease/polkit", "detached", true, None));
        assert_eq!(l.len(), 1, "the searched region is a fact, not an absence");
        assert!(l.report()[0].complete);
    }

    #[test]
    fn jsonl_round_trips() {
        let mut l = CoverageLedger::new();
        l.upsert(fact("aegloss", "approve/decision", "r1", true, None));
        l.upsert(fact("aegloss", "approve/decision", "r2", false, Some("Poisoned")));
        let dir = std::env::temp_dir();
        let path = dir.join(format!("smash-coverage-{}.jsonl", std::process::id()));
        l.write_jsonl(&path).unwrap();
        let back = CoverageLedger::read_jsonl(&path).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back.report(), l.report());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn coverage_status_serializes_snake_case() {
        assert_eq!(serde_json::to_string(&CoverageStatus::Sampled).unwrap(), "\"sampled\"");
        assert_eq!(serde_json::to_string(&CoverageStatus::Unvisited).unwrap(), "\"unvisited\"");
    }
}
