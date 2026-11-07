//! The append-only ledger — distinct candidates, dedup'd by canonical key, with
//! JSONL persistence.
//!
//! Dedup is the property that keeps "managed well" true at volume: the ledger holds
//! **one row per distinct `candidate_key`**, and a re-surfaced candidate bumps its
//! occurrence count and refreshes its latest evidence rather than creating a second
//! row — so the ledger grows with *distinct candidates*, not with *total runs*.
//!
//! A merge never touches the row's **identity or human decisions**. The canonical key
//! is derived from template + params + target + effect + oracle, so those fields are
//! identical across a re-surface by construction and are left alone; the lifecycle
//! disposition and the cluster assignment are the human's and are never overwritten by
//! a mechanical re-surface. Only the mechanical facts move: occurrence count, the
//! seen-timestamps, the latest bundle, the latest verdict/fidelity, and any new
//! provenance variant.
//!
//! Persistence is a deterministic JSONL snapshot — one record per line, ordered by key
//! (the ledger keeps records in a `BTreeMap`). An updates-log layer on top is a later
//! refinement; one line per distinct key is what `specs/findings-management.md` §8
//! calls for to start.

use crate::record::{CandidateKey, CandidateRecord};
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

/// The in-memory ledger: `CandidateKey → CandidateRecord`, kept sorted for a
/// deterministic snapshot.
#[derive(Clone, Debug, Default)]
pub struct Ledger {
    records: BTreeMap<CandidateKey, CandidateRecord>,
}

impl Ledger {
    pub fn new() -> Self {
        Ledger::default()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, key: &CandidateKey) -> Option<&CandidateRecord> {
        self.records.get(key)
    }

    /// Mutable access, so a caller can apply a lifecycle transition to a stored row.
    pub fn get_mut(&mut self, key: &CandidateKey) -> Option<&mut CandidateRecord> {
        self.records.get_mut(key)
    }

    /// Records in key order (deterministic).
    pub fn iter(&self) -> impl Iterator<Item = &CandidateRecord> {
        self.records.values()
    }

    /// Insert a new candidate, or dedup-merge an already-present one. Returns `true` if
    /// a new row was created, `false` if an existing row was merged into.
    ///
    /// On merge the mechanical facts move and the row's identity + human decisions stay
    /// put (see the module docs): occurrence count accrues, `first_seen`/`last_seen`
    /// widen, the latest non-empty bundle and the latest verdict/fidelity win (the row
    /// reflects its most recent run; the *finding status* lives in the disposition, not
    /// here), and new provenance variants are appended once.
    pub fn upsert(&mut self, incoming: CandidateRecord) -> bool {
        match self.records.get_mut(&incoming.candidate_key) {
            None => {
                self.records.insert(incoming.candidate_key.clone(), incoming);
                true
            }
            Some(existing) => {
                existing.occurrence_count = existing
                    .occurrence_count
                    .saturating_add(incoming.occurrence_count);
                existing.first_seen = existing.first_seen.min(incoming.first_seen);
                existing.last_seen = existing.last_seen.max(incoming.last_seen);
                if incoming.bundle_ref.is_some() {
                    existing.bundle_ref = incoming.bundle_ref;
                }
                if incoming.verdict.is_some() {
                    existing.verdict = incoming.verdict;
                    existing.evidence_fidelity = incoming.evidence_fidelity;
                }
                for p in incoming.provenance_variants {
                    if !existing.provenance_variants.contains(&p) {
                        existing.provenance_variants.push(p);
                    }
                }
                // Left untouched: candidate_key, template, target_handle, effect_class,
                // oracle (identity, equal by construction), and disposition + cluster_id
                // (the human's).
                false
            }
        }
    }

    /// Write the ledger as JSONL — one record per line, in key order. Deterministic:
    /// the same ledger always produces byte-identical output.
    pub fn write_jsonl(&self, path: &Path) -> io::Result<()> {
        let mut out = String::new();
        for record in self.records.values() {
            let line = serde_json::to_string(record)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            out.push_str(&line);
            out.push('\n');
        }
        std::fs::write(path, out)
    }

    /// Read a ledger from a JSONL snapshot. Blank lines are ignored; a malformed line
    /// is an error (fail closed — a ledger that can't be read is not silently empty).
    /// Records are loaded as-is (no re-merge); duplicate keys in the file keep the last.
    pub fn read_jsonl(path: &Path) -> io::Result<Ledger> {
        let text = std::fs::read_to_string(path)?;
        let mut ledger = Ledger::new();
        for (lineno, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let record: CandidateRecord = serde_json::from_str(line).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("ledger line {}: {e}", lineno + 1),
                )
            })?;
            ledger.records.insert(record.candidate_key.clone(), record);
        }
        Ok(ledger)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{
        AdmissionOutcome, BundleRef, CandidateKey, CandidateRecord, EvidenceFidelity,
        LifecycleState, ProvenanceRecord, Transition, VerdictClass,
    };

    fn rec(key: &str, now: u64) -> CandidateRecord {
        CandidateRecord::surfaced(
            CandidateKey(key.into()),
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
            now,
        )
    }

    fn prov(seed: u64) -> ProvenanceRecord {
        ProvenanceRecord {
            generator_id: "model-free".into(),
            generator_version: 1,
            source: "seed".into(),
            seed,
        }
    }

    #[test]
    fn first_upsert_is_a_new_row() {
        let mut l = Ledger::new();
        assert!(l.upsert(rec("k1", 100)));
        assert_eq!(l.len(), 1);
        assert_eq!(l.get(&CandidateKey("k1".into())).unwrap().occurrence_count, 1);
    }

    #[test]
    fn re_surface_bumps_occurrence_not_rows() {
        let mut l = Ledger::new();
        assert!(l.upsert(rec("k1", 100)));
        assert!(!l.upsert(rec("k1", 200)), "second surface is a merge, not a new row");
        assert_eq!(l.len(), 1, "still one row");
        let r = l.get(&CandidateKey("k1".into())).unwrap();
        assert_eq!(r.occurrence_count, 2);
        assert_eq!(r.first_seen, 100);
        assert_eq!(r.last_seen, 200, "last_seen widened to the newer surface");
    }

    #[test]
    fn distinct_keys_are_distinct_rows() {
        let mut l = Ledger::new();
        l.upsert(rec("k1", 100));
        l.upsert(rec("k2", 100));
        assert_eq!(l.len(), 2);
    }

    #[test]
    fn merge_appends_new_provenance_variants_once() {
        let mut l = Ledger::new();
        let mut a = rec("k1", 100);
        a.provenance_variants = vec![prov(7)];
        l.upsert(a);

        let mut b = rec("k1", 200);
        b.provenance_variants = vec![prov(7), prov(9)]; // 7 is a dup, 9 is new
        l.upsert(b);

        let r = l.get(&CandidateKey("k1".into())).unwrap();
        assert_eq!(r.provenance_variants.len(), 2, "7 deduped, 9 appended");
        assert!(r.provenance_variants.iter().any(|p| p.seed == 9));
    }

    #[test]
    fn merge_preserves_human_decisions() {
        // A ratified row keeps its disposition and cluster through a mechanical re-surface.
        let mut l = Ledger::new();
        let mut a = rec("k1", 100);
        a.cluster_id = Some(crate::record::ClusterId("url-token".into()));
        a.disposition.history.push(Transition::new(
            LifecycleState::Triaged,
            "jarmo",
            150,
            "clustered",
        ));
        l.upsert(a);

        // Re-surface: a fresh Surfaced record for the same key must NOT reset triage.
        l.upsert(rec("k1", 300));
        let r = l.get(&CandidateKey("k1".into())).unwrap();
        assert_eq!(r.state(), LifecycleState::Triaged, "disposition preserved");
        assert_eq!(r.cluster_id, Some(crate::record::ClusterId("url-token".into())));
        assert_eq!(r.occurrence_count, 2);
    }

    #[test]
    fn merge_takes_the_latest_bundle_and_verdict() {
        let mut l = Ledger::new();
        l.upsert(rec("k1", 100)); // Kill / ResponseOnly / no bundle

        let mut fixed = rec("k1", 400);
        fixed.verdict = Some(VerdictClass::Defended); // re-run after a fix
        fixed.evidence_fidelity = EvidenceFidelity::EffectConfirmed;
        fixed.bundle_ref = Some(BundleRef {
            path: "smash-runs/post-fix.json".into(),
            digest: "deadbeef".into(),
        });
        l.upsert(fixed);

        let r = l.get(&CandidateKey("k1".into())).unwrap();
        assert_eq!(r.verdict, Some(VerdictClass::Defended), "latest run wins the summary");
        assert_eq!(r.evidence_fidelity, EvidenceFidelity::EffectConfirmed);
        assert_eq!(r.bundle_ref.as_ref().unwrap().digest, "deadbeef");
    }

    #[test]
    fn jsonl_round_trips_and_is_deterministic() {
        let mut l = Ledger::new();
        l.upsert(rec("k2", 100));
        l.upsert(rec("k1", 100));
        l.upsert(rec("k1", 200)); // merge

        let dir = std::env::temp_dir();
        let path = dir.join(format!("smash-ledger-{}.jsonl", std::process::id()));
        l.write_jsonl(&path).unwrap();

        // Deterministic: writing twice gives byte-identical output.
        let first = std::fs::read_to_string(&path).unwrap();
        l.write_jsonl(&path).unwrap();
        let second = std::fs::read_to_string(&path).unwrap();
        assert_eq!(first, second);
        // Two lines (k1 merged, k2), in key order.
        assert_eq!(first.lines().count(), 2);

        let back = Ledger::read_jsonl(&path).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back.get(&CandidateKey("k1".into())).unwrap().occurrence_count, 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_ignores_blank_lines_and_fails_closed_on_garbage() {
        let dir = std::env::temp_dir();
        let good = dir.join(format!("smash-ledger-good-{}.jsonl", std::process::id()));
        let r = rec("k1", 100);
        let line = serde_json::to_string(&r).unwrap();
        std::fs::write(&good, format!("\n{line}\n\n")).unwrap();
        let l = Ledger::read_jsonl(&good).unwrap();
        assert_eq!(l.len(), 1);
        let _ = std::fs::remove_file(&good);

        let bad = dir.join(format!("smash-ledger-bad-{}.jsonl", std::process::id()));
        std::fs::write(&bad, "{not valid json}\n").unwrap();
        assert!(Ledger::read_jsonl(&bad).is_err(), "a malformed ledger is an error, not empty");
        let _ = std::fs::remove_file(&bad);
    }

    #[test]
    fn get_mut_allows_a_stored_transition() {
        let mut l = Ledger::new();
        l.upsert(rec("k1", 100));
        let key = CandidateKey("k1".into());
        crate::lifecycle::apply_transition(
            l.get_mut(&key).unwrap(),
            LifecycleState::Triaged,
            "jarmo",
            150,
            "triaging in place",
        )
        .unwrap();
        assert_eq!(l.get(&key).unwrap().state(), LifecycleState::Triaged);
    }
}
