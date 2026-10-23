//! Verdict types: the five-state outcome contract.
//!
//! Every technique execution ends with exactly one [`Verdict`]. The five
//! states partition the outcome space completely — there is no sixth state,
//! no silent swallowing, no "we'll figure it out later."
//!
//! ## The five states
//!
//! | Verdict        | Meaning |
//! |----------------|---------|
//! | **Pass**        | The target enforced the invariant under the tested conditions. |
//! | **Fail**        | The target violated the invariant; evidence is attached. |
//! | **Inconclusive**| The test ran but could not determine the outcome. |
//! | **Denied**      | The test was refused before any probe fired (scope/authority/budget). |
//! | **Error**       | Infrastructure failure unrelated to the target's security posture. |
//!
//! ## Design constraints
//!
//! - **Inconclusive ≠ Pass.** A run with any inconclusive, denied, or errored
//!   technique cannot produce exit code 0. The CLI uses exit 2 for "no confirmed
//!   failure but incomplete coverage."
//! - **Denied is a fact, not an error.** The capability gate refused the call
//!   before it left the building. The match log records this as a replayable
//!   event. Denials carry the [`Denial`](crate::capability::Denial) reason.
//! - **Error is infrastructure, not security.** A timeout, a DNS failure, a
//!   serialization bug — these say nothing about the target's posture.
//! - **Fail carries evidence.** A bare "fail" is useless; the verdict must
//!   reference what was observed and what was expected.
//! - Forward-compatible: [`Verdict`] is `#[non_exhaustive]`.

use crate::capability::Denial;
use crate::fighter::TechniqueName;
use std::fmt;

// ── Evidence references ──────────────────────────────────────────────────

/// An identifier pointing to a stored evidence artifact (log entry, receipt,
/// observation record). The actual artifact lives in the evidence bundle; this
/// is the handle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvidenceRef(String);

impl EvidenceRef {
    pub fn new(id: impl Into<String>) -> Self {
        EvidenceRef(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EvidenceRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── Verdict ──────────────────────────────────────────────────────────────

/// The outcome of a single technique execution. One of five states; no
/// implicit "unknown" or "skipped" — if a technique didn't run, there is
/// no `TechniqueVerdict` for it, and the coverage count reflects the gap.
///
/// Forward-compatible: new variants may be added in future versions.
/// Match arms must include a wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    /// The target enforced the invariant under the tested conditions.
    /// Evidence references support the claim.
    Pass {
        /// References to evidence artifacts that support the pass verdict.
        evidence: Vec<EvidenceRef>,
    },

    /// The target violated the invariant. This is the critical finding —
    /// the whole point of running Smash.
    Fail {
        /// What was expected (the invariant that should have held).
        expected: String,
        /// What was actually observed.
        observed: String,
        /// References to evidence artifacts that prove the violation.
        evidence: Vec<EvidenceRef>,
    },

    /// The test ran but could not determine pass or fail. Common causes:
    /// ambiguous signals, threshold not met, partial observation.
    ///
    /// **Not a pass.** A run with any inconclusive verdict gets CLI exit 2.
    Inconclusive {
        /// Why the verdict couldn't be determined.
        reason: String,
        /// Any partial evidence collected before the determination stalled.
        evidence: Vec<EvidenceRef>,
    },

    /// The capability gate refused the call before any probe fired.
    /// This is a structural fact about the match configuration, not a
    /// target behavior. Denials are replayable and logged.
    Denied {
        /// The gate's denial reason.
        denial: Denial,
    },

    /// Infrastructure failure unrelated to the target's security posture.
    /// DNS failures, serialization bugs, harness panics — these say nothing
    /// about whether the target enforces its invariants.
    Error {
        /// What went wrong.
        message: String,
    },
}

impl Verdict {
    /// Whether this verdict represents a confirmed security failure.
    pub fn is_fail(&self) -> bool {
        matches!(self, Verdict::Fail { .. })
    }

    /// Whether this verdict is a clean pass with supporting evidence.
    pub fn is_pass(&self) -> bool {
        matches!(self, Verdict::Pass { .. })
    }

    /// Whether this verdict prevents the run from being considered complete.
    /// Inconclusive, Denied, and Error all count as incomplete — the run
    /// cannot claim full coverage.
    pub fn is_incomplete(&self) -> bool {
        matches!(
            self,
            Verdict::Inconclusive { .. } | Verdict::Denied { .. } | Verdict::Error { .. }
        )
    }

    /// Collect all evidence references, regardless of verdict state.
    /// Returns an empty slice for Denied and Error (which carry no evidence).
    pub fn evidence(&self) -> &[EvidenceRef] {
        match self {
            Verdict::Pass { evidence }
            | Verdict::Fail { evidence, .. }
            | Verdict::Inconclusive { evidence, .. } => evidence,
            Verdict::Denied { .. } | Verdict::Error { .. } => &[],
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Pass { .. } => f.write_str("pass"),
            Verdict::Fail { expected, observed, .. } => {
                write!(f, "FAIL: expected {expected}, observed {observed}")
            }
            Verdict::Inconclusive { reason, .. } => {
                write!(f, "inconclusive: {reason}")
            }
            Verdict::Denied { denial } => {
                write!(f, "denied: {denial}")
            }
            Verdict::Error { message } => {
                write!(f, "error: {message}")
            }
        }
    }
}

// ── Per-technique verdict ────────────────────────────────────────────────

/// A verdict bound to the technique that produced it. This is what the
/// match log records and the report renders.
#[derive(Debug, Clone)]
pub struct TechniqueVerdict {
    technique: TechniqueName,
    verdict: Verdict,
}

impl TechniqueVerdict {
    pub fn new(technique: TechniqueName, verdict: Verdict) -> Self {
        TechniqueVerdict { technique, verdict }
    }

    pub fn technique(&self) -> &TechniqueName {
        &self.technique
    }

    pub fn verdict(&self) -> &Verdict {
        &self.verdict
    }
}

impl fmt::Display for TechniqueVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.technique, self.verdict)
    }
}

// ── Run-level summary ────────────────────────────────────────────────────

/// Aggregate verdict counts for a completed (or aborted) run.
/// Maps directly to the report's required/executed/passed/failed/incomplete
/// counts and the CLI exit code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerdictSummary {
    /// Total techniques the run was configured to execute.
    pub required: u32,
    /// Techniques that actually produced a verdict (pass + fail + inconclusive).
    pub executed: u32,
    /// Techniques that passed.
    pub passed: u32,
    /// Techniques that confirmed a security failure.
    pub failed: u32,
    /// Techniques that were inconclusive, denied, or errored.
    pub incomplete: u32,
}

impl VerdictSummary {
    /// Compute from a slice of technique verdicts and the total required count.
    pub fn from_verdicts(required: u32, verdicts: &[TechniqueVerdict]) -> Self {
        let mut passed = 0u32;
        let mut failed = 0u32;
        let mut incomplete = 0u32;

        for tv in verdicts {
            match &tv.verdict {
                Verdict::Pass { .. } => passed += 1,
                Verdict::Fail { .. } => failed += 1,
                Verdict::Inconclusive { .. }
                | Verdict::Denied { .. }
                | Verdict::Error { .. } => incomplete += 1,
            }
        }

        VerdictSummary {
            required,
            executed: passed + failed + incomplete,
            passed,
            failed,
            incomplete,
        }
    }

    /// The CLI exit code this summary produces.
    ///
    /// | Exit | Condition |
    /// |------|-----------|
    /// | `0`  | All required passed, no failures, no incomplete. |
    /// | `1`  | At least one confirmed security failure. |
    /// | `2`  | No failure, but coverage is incomplete or zero tests executed. |
    pub fn exit_code(&self) -> u8 {
        if self.failed > 0 {
            1
        } else if self.incomplete > 0 || self.executed == 0 || self.passed < self.required {
            2
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{Authority, Target};

    // ── Verdict state tests ──────────────────────────────────────────

    #[test]
    fn pass_is_pass_and_not_incomplete() {
        let v = Verdict::Pass {
            evidence: vec![EvidenceRef::new("obs-001")],
        };
        assert!(v.is_pass());
        assert!(!v.is_fail());
        assert!(!v.is_incomplete());
    }

    #[test]
    fn fail_is_fail_and_not_incomplete() {
        let v = Verdict::Fail {
            expected: "reject write".into(),
            observed: "write succeeded".into(),
            evidence: vec![EvidenceRef::new("obs-002")],
        };
        assert!(v.is_fail());
        assert!(!v.is_pass());
        assert!(!v.is_incomplete());
    }

    #[test]
    fn inconclusive_is_incomplete() {
        let v = Verdict::Inconclusive {
            reason: "ambiguous timing".into(),
            evidence: vec![],
        };
        assert!(v.is_incomplete());
        assert!(!v.is_pass());
        assert!(!v.is_fail());
    }

    #[test]
    fn denied_is_incomplete() {
        let v = Verdict::Denied {
            denial: Denial::OutOfScope {
                target: Target::new("http://evil.example.com"),
            },
        };
        assert!(v.is_incomplete());
        assert!(!v.is_pass());
        assert!(!v.is_fail());
    }

    #[test]
    fn error_is_incomplete() {
        let v = Verdict::Error {
            message: "DNS resolution failed".into(),
        };
        assert!(v.is_incomplete());
    }

    // ── Evidence access ──────────────────────────────────────────────

    #[test]
    fn pass_evidence_is_accessible() {
        let refs = vec![EvidenceRef::new("e1"), EvidenceRef::new("e2")];
        let v = Verdict::Pass {
            evidence: refs.clone(),
        };
        assert_eq!(v.evidence(), &refs);
    }

    #[test]
    fn fail_evidence_is_accessible() {
        let refs = vec![EvidenceRef::new("e3")];
        let v = Verdict::Fail {
            expected: "deny".into(),
            observed: "allow".into(),
            evidence: refs.clone(),
        };
        assert_eq!(v.evidence(), &refs);
    }

    #[test]
    fn denied_has_no_evidence() {
        let v = Verdict::Denied {
            denial: Denial::AuthorityExceeded {
                required: Authority::Mutating,
                ceiling: Authority::ReadOnly,
            },
        };
        assert!(v.evidence().is_empty());
    }

    #[test]
    fn error_has_no_evidence() {
        let v = Verdict::Error {
            message: "timeout".into(),
        };
        assert!(v.evidence().is_empty());
    }

    // ── Display ──────────────────────────────────────────────────────

    #[test]
    fn display_formats() {
        let pass = Verdict::Pass { evidence: vec![] };
        assert_eq!(pass.to_string(), "pass");

        let fail = Verdict::Fail {
            expected: "reject".into(),
            observed: "accept".into(),
            evidence: vec![],
        };
        assert_eq!(fail.to_string(), "FAIL: expected reject, observed accept");

        let inc = Verdict::Inconclusive {
            reason: "partial data".into(),
            evidence: vec![],
        };
        assert_eq!(inc.to_string(), "inconclusive: partial data");
    }

    // ── TechniqueVerdict ─────────────────────────────────────────────

    #[test]
    fn technique_verdict_display() {
        use crate::fighter::TechniqueName;

        let tv = TechniqueVerdict::new(
            TechniqueName::new("write-via-readonly-session"),
            Verdict::Fail {
                expected: "deny write".into(),
                observed: "write succeeded".into(),
                evidence: vec![EvidenceRef::new("obs-007")],
            },
        );
        assert_eq!(
            tv.to_string(),
            "[write-via-readonly-session] FAIL: expected deny write, observed write succeeded"
        );
    }

    // ── VerdictSummary + exit codes ──────────────────────────────────

    #[test]
    fn all_pass_exit_zero() {
        use crate::fighter::TechniqueName;

        let verdicts = vec![
            TechniqueVerdict::new(
                TechniqueName::new("t1"),
                Verdict::Pass {
                    evidence: vec![EvidenceRef::new("e1")],
                },
            ),
            TechniqueVerdict::new(
                TechniqueName::new("t2"),
                Verdict::Pass {
                    evidence: vec![EvidenceRef::new("e2")],
                },
            ),
        ];
        let summary = VerdictSummary::from_verdicts(2, &verdicts);
        assert_eq!(summary.exit_code(), 0);
        assert_eq!(summary.passed, 2);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.incomplete, 0);
    }

    #[test]
    fn any_fail_exit_one() {
        use crate::fighter::TechniqueName;

        let verdicts = vec![
            TechniqueVerdict::new(
                TechniqueName::new("t1"),
                Verdict::Pass {
                    evidence: vec![],
                },
            ),
            TechniqueVerdict::new(
                TechniqueName::new("t2"),
                Verdict::Fail {
                    expected: "deny".into(),
                    observed: "allow".into(),
                    evidence: vec![EvidenceRef::new("e3")],
                },
            ),
        ];
        let summary = VerdictSummary::from_verdicts(2, &verdicts);
        assert_eq!(summary.exit_code(), 1);
        assert_eq!(summary.failed, 1);
    }

    #[test]
    fn inconclusive_exit_two() {
        use crate::fighter::TechniqueName;

        let verdicts = vec![
            TechniqueVerdict::new(
                TechniqueName::new("t1"),
                Verdict::Pass {
                    evidence: vec![],
                },
            ),
            TechniqueVerdict::new(
                TechniqueName::new("t2"),
                Verdict::Inconclusive {
                    reason: "ambiguous".into(),
                    evidence: vec![],
                },
            ),
        ];
        let summary = VerdictSummary::from_verdicts(2, &verdicts);
        assert_eq!(summary.exit_code(), 2);
        assert_eq!(summary.incomplete, 1);
    }

    #[test]
    fn zero_executed_exit_two() {
        let summary = VerdictSummary::from_verdicts(3, &[]);
        assert_eq!(summary.exit_code(), 2);
        assert_eq!(summary.executed, 0);
    }

    #[test]
    fn fewer_passed_than_required_exit_two() {
        use crate::fighter::TechniqueName;

        // 3 required but only 2 ran and passed
        let verdicts = vec![
            TechniqueVerdict::new(
                TechniqueName::new("t1"),
                Verdict::Pass { evidence: vec![] },
            ),
            TechniqueVerdict::new(
                TechniqueName::new("t2"),
                Verdict::Pass { evidence: vec![] },
            ),
        ];
        let summary = VerdictSummary::from_verdicts(3, &verdicts);
        assert_eq!(summary.exit_code(), 2);
    }

    #[test]
    fn denied_counts_as_incomplete() {
        use crate::fighter::TechniqueName;

        let verdicts = vec![TechniqueVerdict::new(
            TechniqueName::new("t1"),
            Verdict::Denied {
                denial: Denial::OutOfScope {
                    target: Target::new("http://127.0.0.1:9999"),
                },
            },
        )];
        let summary = VerdictSummary::from_verdicts(1, &verdicts);
        assert_eq!(summary.incomplete, 1);
        assert_eq!(summary.exit_code(), 2);
    }

    #[test]
    fn evidence_ref_display() {
        let r = EvidenceRef::new("obs-001");
        assert_eq!(r.to_string(), "obs-001");
        assert_eq!(r.as_str(), "obs-001");
    }
}
