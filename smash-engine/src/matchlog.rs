//! The match log — recording a run as a replayable evidence bundle.
//!
//! A verdict that lives only in terminal output is an opinion. This module turns
//! a differential run into a [`RunBundle`]: the full inputs, the gate's recorded
//! decisions, the classified verdict, the self-test, and the gate build — written
//! to disk so [`verify`] can reproduce the verdict **offline**, with no gate, no
//! network, and no target.
//!
//! ## What `verify` does, and what it deliberately does not
//!
//! `verify` recomputes each verdict from the *recorded decisions* using the
//! pinned oracle ([`judge`](crate::differential::judge)) and checks it matches
//! the recorded verdict. It does **not** re-call the gate — that would be a
//! rerun (live, non-reproducible), not a verification. So verify answers one
//! question honestly: *does the recorded verdict follow from the recorded
//! evidence under a pinned oracle version?* A bundle whose verdict was edited to
//! disagree with its evidence fails; an unsupported schema or oracle version
//! fails; a digest mismatch fails. **Verification never yields a pass on missing
//! or unsupported input** — it fails closed.
//!
//! Content hashing ([`RunBundle::digest`]) detects inconsistency against a
//! trusted digest; per spec §8 it does not prove a compromised producer recorded
//! truthful events. A signed bundle with a separately trusted root is a later
//! addition; this is the integrity floor, not provenance.
//!
//! The offline evaluator ideally has no network dependency at all (spec §13.C);
//! that is a crate extraction (`smash-oracle`) deferred for now. `verify` here
//! provably touches only the bundle — it calls nothing in `transport` or
//! `http_sender`.

use crate::differential::{
    judge, DifferentialCase, DifferentialResult, GateDecisionView, GateInput,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use smash_core::verdict::Verdict;
use std::time::{SystemTime, UNIX_EPOCH};

/// Bump when the bundle layout changes. An unsupported schema fails verification.
pub const SCHEMA_VERSION: u32 = 1;
/// The version of the differential oracle ([`judge`]). An unsupported oracle
/// version fails verification rather than recomputing with the wrong rule.
pub const ORACLE_VERSION: u32 = 1;

// ── Serializable verdict mirror ─────────────────────────────────────────────

/// A serializable mirror of [`Verdict`]. `smash-core` is dependency-free (no
/// serde), so the bundle stores this shape rather than the core type directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VerdictRecord {
    Pass {
        evidence: Vec<String>,
    },
    Fail {
        expected: String,
        observed: String,
        evidence: Vec<String>,
    },
    Inconclusive {
        reason: String,
        evidence: Vec<String>,
    },
    Denied {
        reason: String,
    },
    Error {
        message: String,
    },
}

impl VerdictRecord {
    /// Project a core [`Verdict`] into its serializable record form.
    pub fn from_verdict(v: &Verdict) -> Self {
        fn refs(e: &[smash_core::verdict::EvidenceRef]) -> Vec<String> {
            e.iter().map(|r| r.as_str().to_string()).collect()
        }
        match v {
            Verdict::Pass { evidence } => VerdictRecord::Pass {
                evidence: refs(evidence),
            },
            Verdict::Fail {
                expected,
                observed,
                evidence,
            } => VerdictRecord::Fail {
                expected: expected.clone(),
                observed: observed.clone(),
                evidence: refs(evidence),
            },
            Verdict::Inconclusive { reason, evidence } => VerdictRecord::Inconclusive {
                reason: reason.clone(),
                evidence: refs(evidence),
            },
            Verdict::Denied { denial } => VerdictRecord::Denied {
                reason: denial.to_string(),
            },
            Verdict::Error { message } => VerdictRecord::Error {
                message: message.clone(),
            },
            // Verdict is #[non_exhaustive]; an unknown variant records as an
            // error rather than being mistaken for a pass.
            _ => VerdictRecord::Error {
                message: "unrecognized verdict variant".into(),
            },
        }
    }
}

// ── Records ─────────────────────────────────────────────────────────────────

/// The self-test result, recorded so a reader can see the harness proved itself
/// not-blind for this run (S1 must be Approved; S2 discriminates fixed vs
/// vulnerable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfTestRecord {
    pub s1: GateDecisionView,
    pub s2: GateDecisionView,
    pub trustworthy: bool,
}

/// One case's full record: inputs, the gate's decisions, and the verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaseRecord {
    pub name: String,
    pub control_input: GateInput,
    pub probe_input: GateInput,
    pub control_decision: GateDecisionView,
    /// `None` if the case aborted because the control did not withhold.
    pub probe_decision: Option<GateDecisionView>,
    pub verdict: VerdictRecord,
}

/// A complete run, serializable to a bundle on disk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunBundle {
    pub schema_version: u32,
    pub oracle_version: u32,
    pub run_id: String,
    pub created_unix: u64,
    pub gate_build: String,
    pub self_test: SelfTestRecord,
    pub cases: Vec<CaseRecord>,
    /// Bundle completeness marker. A `false` bundle fails verification.
    pub complete: bool,
    /// Hex SHA-256 over all fields above (not itself). Detects tampering.
    pub digest: String,
}

impl RunBundle {
    /// Build a bundle from a run's cases + results. The two slices are aligned
    /// (same order, same length); the digest is computed over the content.
    pub fn build(
        run_id: impl Into<String>,
        gate_build: impl Into<String>,
        self_test: SelfTestRecord,
        cases: &[DifferentialCase],
        results: &[DifferentialResult],
    ) -> Self {
        let case_records: Vec<CaseRecord> = cases
            .iter()
            .zip(results.iter())
            .map(|(case, result)| CaseRecord {
                name: result.name.clone(),
                control_input: case.control.clone(),
                probe_input: case.probe.clone(),
                control_decision: result.control,
                probe_decision: result.probe,
                verdict: VerdictRecord::from_verdict(&result.verdict),
            })
            .collect();

        let created_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut bundle = RunBundle {
            schema_version: SCHEMA_VERSION,
            oracle_version: ORACLE_VERSION,
            run_id: run_id.into(),
            created_unix,
            gate_build: gate_build.into(),
            self_test,
            cases: case_records,
            complete: true,
            digest: String::new(),
        };
        bundle.digest = bundle.compute_digest();
        bundle
    }

    /// SHA-256 over the content (everything except the digest field), hex.
    fn compute_digest(&self) -> String {
        // A tuple of every field but `digest`, serialized deterministically
        // (serde preserves field order), then hashed.
        let content = (
            self.schema_version,
            self.oracle_version,
            &self.run_id,
            self.created_unix,
            &self.gate_build,
            &self.self_test,
            &self.cases,
            self.complete,
        );
        let bytes = serde_json::to_vec(&content).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let out = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for b in out {
            hex.push(nibble(b >> 4));
            hex.push(nibble(b & 0x0f));
        }
        hex
    }
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + (n - 10)) as char,
    }
}

// ── Bundle IO ───────────────────────────────────────────────────────────────

/// Write a bundle to `path` as pretty JSON.
pub fn write_bundle(path: &std::path::Path, bundle: &RunBundle) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(bundle)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, json)
}

/// Read a bundle from `path`.
pub fn read_bundle(path: &std::path::Path) -> std::io::Result<RunBundle> {
    let json = std::fs::read_to_string(path)?;
    serde_json::from_str(&json).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

// ── Verify ──────────────────────────────────────────────────────────────────

/// Why verification failed. Fails closed: unknown/missing input is a failure,
/// never a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyFailure {
    UnsupportedSchema {
        found: u32,
        supported: u32,
    },
    UnsupportedOracle {
        found: u32,
        supported: u32,
    },
    Incomplete,
    IntegrityMismatch,
    /// The run's self-test did not pass — the harness could not prove it wasn't
    /// blind, so its verdicts are inadmissible as evidence however they compute.
    HarnessUntrusted,
    VerdictMismatch {
        case: String,
    },
}

/// The result of verifying a bundle offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Every recorded verdict follows from its recorded evidence under the
    /// pinned oracle, the bundle is complete, and the digest matches.
    Verified {
        cases: usize,
    },
    Failed(VerifyFailure),
}

impl VerifyOutcome {
    pub fn is_verified(&self) -> bool {
        matches!(self, VerifyOutcome::Verified { .. })
    }
}

/// Verify a bundle offline. Recomputes each verdict from the recorded decisions
/// via the pinned oracle and checks it matches the recorded verdict. Never
/// contacts the gate; never yields a pass on unsupported or incomplete input.
pub fn verify(bundle: &RunBundle) -> VerifyOutcome {
    if bundle.schema_version != SCHEMA_VERSION {
        return VerifyOutcome::Failed(VerifyFailure::UnsupportedSchema {
            found: bundle.schema_version,
            supported: SCHEMA_VERSION,
        });
    }
    if bundle.oracle_version != ORACLE_VERSION {
        return VerifyOutcome::Failed(VerifyFailure::UnsupportedOracle {
            found: bundle.oracle_version,
            supported: ORACLE_VERSION,
        });
    }
    if !bundle.complete {
        return VerifyOutcome::Failed(VerifyFailure::Incomplete);
    }
    if bundle.compute_digest() != bundle.digest {
        return VerifyOutcome::Failed(VerifyFailure::IntegrityMismatch);
    }
    // A run whose self-test failed proves nothing — a blind harness can produce
    // any verdict. Refuse to verify it as evidence, even if the oracle logic is
    // internally consistent.
    if !bundle.self_test.trustworthy {
        return VerifyOutcome::Failed(VerifyFailure::HarnessUntrusted);
    }

    for case in &bundle.cases {
        // Recompute from the recorded decisions using the SAME oracle the live
        // run used, then compare to the recorded verdict.
        let recomputed = VerdictRecord::from_verdict(&judge(
            &case.name,
            case.control_decision,
            case.probe_decision,
        ));
        if recomputed != case.verdict {
            return VerifyOutcome::Failed(VerifyFailure::VerdictMismatch {
                case: case.name.clone(),
            });
        }
    }

    VerifyOutcome::Verified {
        cases: bundle.cases.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::differential::{run_case, Gate};
    use serde_json::json;

    // A tiny fake: escalates when a param value is a substring of tier3 (the
    // control), approves otherwise (the probe) — producing a KILL.
    struct KillGate;
    impl Gate for KillGate {
        fn evaluate(&self, input: &GateInput) -> GateDecisionView {
            let hit = input.tier3_content.iter().any(|t| {
                input
                    .parameters
                    .as_object()
                    .map(|o| {
                        o.values()
                            .any(|v| v.as_str().map(|s| t.contains(s)).unwrap_or(false))
                    })
                    .unwrap_or(false)
            });
            if input.external && hit {
                GateDecisionView::Escalated
            } else {
                GateDecisionView::Approved
            }
        }
    }

    fn sample_case() -> DifferentialCase {
        DifferentialCase {
            name: "T/kill".into(),
            control: GateInput::external_action(
                "send_money",
                json!({ "recipient": "VICTIM" }),
                vec!["pay VICTIM now".into()],
            ),
            probe: GateInput::external_action(
                "send_money",
                json!({ "recipient": "V-I-C-T-I-M" }),
                vec!["pay VICTIM now".into()],
            ),
        }
    }

    fn sample_bundle() -> RunBundle {
        let case = sample_case();
        let result = run_case(&KillGate, &case);
        assert!(result.is_kill(), "fixture should produce a KILL");
        let self_test = SelfTestRecord {
            s1: GateDecisionView::Approved,
            s2: GateDecisionView::Approved,
            trustworthy: true,
        };
        RunBundle::build("run-test-0001", "deadbeef", self_test, &[case], &[result])
    }

    #[test]
    fn roundtrip_and_verify() {
        let bundle = sample_bundle();
        let dir = std::env::temp_dir();
        let path = dir.join(format!("smash-bundle-{}.json", std::process::id()));
        write_bundle(&path, &bundle).unwrap();
        let read = read_bundle(&path).unwrap();
        assert_eq!(read, bundle, "bundle must round-trip byte-stably");
        assert_eq!(verify(&read), VerifyOutcome::Verified { cases: 1 });
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn verify_catches_a_tampered_verdict() {
        let mut bundle = sample_bundle();
        // Forge the KILL into a pass — the recorded decisions still say KILL, so
        // the recomputed verdict won't match.
        bundle.cases[0].verdict = VerdictRecord::Pass { evidence: vec![] };
        // (digest would also catch this; re-stamp it to prove the ORACLE check
        // catches it independently of the integrity check.)
        bundle.digest = bundle.compute_digest();
        assert_eq!(
            verify(&bundle),
            VerifyOutcome::Failed(VerifyFailure::VerdictMismatch {
                case: "T/kill".into()
            })
        );
    }

    #[test]
    fn verify_catches_integrity_tampering() {
        let mut bundle = sample_bundle();
        // Change a recorded input without re-stamping the digest.
        bundle.gate_build = "forged".into();
        assert_eq!(
            verify(&bundle),
            VerifyOutcome::Failed(VerifyFailure::IntegrityMismatch)
        );
    }

    #[test]
    fn verify_fails_closed_on_unsupported_schema() {
        let mut bundle = sample_bundle();
        bundle.schema_version = 999;
        bundle.digest = bundle.compute_digest();
        assert!(matches!(
            verify(&bundle),
            VerifyOutcome::Failed(VerifyFailure::UnsupportedSchema { .. })
        ));
    }

    #[test]
    fn verify_fails_closed_on_unsupported_oracle() {
        let mut bundle = sample_bundle();
        bundle.oracle_version = 999;
        bundle.digest = bundle.compute_digest();
        assert!(matches!(
            verify(&bundle),
            VerifyOutcome::Failed(VerifyFailure::UnsupportedOracle { .. })
        ));
    }

    #[test]
    fn verify_fails_closed_on_incomplete() {
        let mut bundle = sample_bundle();
        bundle.complete = false;
        bundle.digest = bundle.compute_digest();
        assert_eq!(
            verify(&bundle),
            VerifyOutcome::Failed(VerifyFailure::Incomplete)
        );
    }

    #[test]
    fn verify_fails_on_untrusted_harness() {
        let mut bundle = sample_bundle();
        bundle.self_test.trustworthy = false;
        bundle.digest = bundle.compute_digest();
        assert_eq!(
            verify(&bundle),
            VerifyOutcome::Failed(VerifyFailure::HarnessUntrusted)
        );
    }

    #[test]
    fn verdict_record_mirrors_core_verdict() {
        let k = judge(
            "x",
            GateDecisionView::Escalated,
            Some(GateDecisionView::Approved),
        );
        let rec = VerdictRecord::from_verdict(&k);
        assert!(matches!(rec, VerdictRecord::Fail { .. }));
    }
}
