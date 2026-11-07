//! Versioned, target-neutral contracts shared by research agents and executors.
//!
//! These are data contracts, not capabilities. An [`ExperimentDraft`] is always
//! untrusted input: an executor must independently authorize and perform it.
//! In particular, these types do not deserialize raw model output directly and
//! do not mark an operation as executed merely because a planner proposed it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// The only research wire schema accepted by the M1 reconnaissance pipeline.
pub const RESEARCH_SCHEMA_VERSION: u32 = 1;
/// Maximum size of an individual free-form contract string.
pub const MAX_RESEARCH_TEXT_BYTES: usize = 16 * 1024;
/// Maximum number of parameters, facts, artifacts, or references in a contract.
pub const MAX_RESEARCH_ITEMS: usize = 256;
/// Reserved serialized space for a final budget-exhausted observation.
pub const TERMINAL_OBSERVATION_RESERVE_BYTES: u64 = 2048;

/// A malformed or semantically inconsistent research contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResearchValidationError(pub String);

impl fmt::Display for ResearchValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ResearchValidationError {}

fn check_version(version: u32) -> Result<(), ResearchValidationError> {
    if version == RESEARCH_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(ResearchValidationError(format!(
            "unsupported research schema {version}; expected {RESEARCH_SCHEMA_VERSION}"
        )))
    }
}

pub fn validate_research_text(field: &str, value: &str) -> Result<(), ResearchValidationError> {
    if value.trim().is_empty() {
        return Err(ResearchValidationError(format!(
            "{field} must not be empty"
        )));
    }
    if value.len() > MAX_RESEARCH_TEXT_BYTES {
        return Err(ResearchValidationError(format!(
            "{field} exceeds {MAX_RESEARCH_TEXT_BYTES} bytes"
        )));
    }
    if value
        .chars()
        .any(|c| c == '\0' || (c.is_control() && c != '\n' && c != '\t'))
    {
        return Err(ResearchValidationError(format!(
            "{field} contains a forbidden control character"
        )));
    }
    Ok(())
}

pub fn validate_research_id(field: &str, value: &str) -> Result<(), ResearchValidationError> {
    validate_research_text(field, value)?;
    if value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ResearchValidationError(format!(
            "{field} must be at most 128 ASCII identifier characters"
        )));
    }
    Ok(())
}

fn check_items<T>(field: &str, values: &[T]) -> Result<(), ResearchValidationError> {
    if values.len() > MAX_RESEARCH_ITEMS {
        Err(ResearchValidationError(format!(
            "{field} exceeds {MAX_RESEARCH_ITEMS} items"
        )))
    } else {
        Ok(())
    }
}

/// The kind of target declared by the operator. M1 executes repositories only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TargetKind {
    Repository,
    HttpServer,
    HostAgent,
    ModelEndpoint,
    ModelArtifact,
    Jailbreak,
}

/// Operator-supplied target identity. The locator is not an authority grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetManifest {
    pub schema_version: u32,
    pub target_id: String,
    pub kind: TargetKind,
    pub locator: String,
    pub description: String,
}

impl TargetManifest {
    pub fn repository(
        target_id: impl Into<String>,
        locator: impl Into<String>,
    ) -> Result<Self, ResearchValidationError> {
        let manifest = Self {
            schema_version: RESEARCH_SCHEMA_VERSION,
            target_id: target_id.into(),
            kind: TargetKind::Repository,
            locator: locator.into(),
            description: "Read-only repository reconnaissance".to_owned(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), ResearchValidationError> {
        check_version(self.schema_version)?;
        validate_research_id("target_id", &self.target_id)?;
        validate_research_text("locator", &self.locator)?;
        validate_research_text("description", &self.description)
    }
}

/// The only authority mode implemented by repository reconnaissance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResearchAuthority {
    ReadOnlyNetworkOff,
}

/// Operator-enforced resource and authority ceiling for one research run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunPolicy {
    pub schema_version: u32,
    pub authority: ResearchAuthority,
    pub max_wall_time_seconds: u64,
    pub max_queries: u32,
    pub max_experiments: u32,
    pub max_completed_experiments: u32,
    pub max_command_seconds: u64,
    pub max_file_bytes: u64,
    pub max_artifact_bytes: u64,
    pub max_total_evidence_bytes: u64,
    pub max_observation_bytes: u64,
    pub max_total_observation_bytes: u64,
    pub max_observations_memory_bytes: u64,
    pub allowed_operations: BTreeSet<ExperimentKind>,
}

impl RunPolicy {
    /// Conservative defaults for local, deterministic repository inspection.
    pub fn repository_read_only() -> Self {
        Self {
            schema_version: RESEARCH_SCHEMA_VERSION,
            authority: ResearchAuthority::ReadOnlyNetworkOff,
            max_wall_time_seconds: 60,
            max_queries: 32,
            max_experiments: 24,
            max_completed_experiments: 24,
            max_command_seconds: 5,
            max_file_bytes: 1024 * 1024,
            max_artifact_bytes: 4 * 1024 * 1024,
            max_total_evidence_bytes: 32 * 1024 * 1024,
            max_observation_bytes: 1024 * 1024,
            max_total_observation_bytes: 8 * 1024 * 1024,
            max_observations_memory_bytes: 16 * 1024 * 1024,
            allowed_operations: BTreeSet::from([
                ExperimentKind::ListFiles,
                ExperimentKind::ReadFile,
                ExperimentKind::ReadManifest,
                ExperimentKind::WorkingTreeStatus,
                ExperimentKind::ReadOnlyCommand,
            ]),
        }
    }

    pub fn validate(&self) -> Result<(), ResearchValidationError> {
        check_version(self.schema_version)?;
        let positive = [
            ("max_wall_time_seconds", self.max_wall_time_seconds),
            ("max_queries", u64::from(self.max_queries)),
            ("max_experiments", u64::from(self.max_experiments)),
            (
                "max_completed_experiments",
                u64::from(self.max_completed_experiments),
            ),
            ("max_command_seconds", self.max_command_seconds),
            ("max_file_bytes", self.max_file_bytes),
            ("max_artifact_bytes", self.max_artifact_bytes),
            ("max_total_evidence_bytes", self.max_total_evidence_bytes),
            ("max_observation_bytes", self.max_observation_bytes),
            (
                "max_total_observation_bytes",
                self.max_total_observation_bytes,
            ),
            (
                "max_observations_memory_bytes",
                self.max_observations_memory_bytes,
            ),
        ];
        for (field, value) in positive {
            if value == 0 {
                return Err(ResearchValidationError(format!("{field} must be positive")));
            }
        }
        // The runner always reserves enough room to serialize a terminal refused
        // observation, including worst-case run and experiment identifiers.
        if self.max_observation_bytes < TERMINAL_OBSERVATION_RESERVE_BYTES {
            return Err(ResearchValidationError(
                "max_observation_bytes is below the terminal-outcome reserve".to_owned(),
            ));
        }
        if self.max_completed_experiments > self.max_experiments {
            return Err(ResearchValidationError(
                "max_completed_experiments exceeds max_experiments".to_owned(),
            ));
        }
        if self.max_observation_bytes > self.max_total_observation_bytes {
            return Err(ResearchValidationError(
                "max_observation_bytes exceeds max_total_observation_bytes".to_owned(),
            ));
        }
        if self.max_total_observation_bytes > self.max_observations_memory_bytes {
            return Err(ResearchValidationError(
                "max_total_observation_bytes exceeds max_observations_memory_bytes".to_owned(),
            ));
        }
        if self.allowed_operations.is_empty() {
            return Err(ResearchValidationError(
                "at least one operation must be allowed".to_owned(),
            ));
        }
        Ok(())
    }
}

/// A narrow operation vocabulary. No variant grants execution authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExperimentKind {
    ListFiles,
    ReadFile,
    ReadManifest,
    WorkingTreeStatus,
    ReadOnlyCommand,
}

/// A planner-proposed experiment, with bounded string parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExperimentDraft {
    pub schema_version: u32,
    pub run_id: String,
    pub sequence: u32,
    pub experiment_id: String,
    pub kind: ExperimentKind,
    pub purpose: String,
    pub expected_evidence: String,
    pub parameters: BTreeMap<String, String>,
}

impl ExperimentDraft {
    pub fn new(
        run_id: impl Into<String>,
        sequence: u32,
        kind: ExperimentKind,
        purpose: impl Into<String>,
    ) -> Self {
        let sequence_text = sequence.to_string();
        Self {
            schema_version: RESEARCH_SCHEMA_VERSION,
            run_id: run_id.into(),
            sequence,
            experiment_id: format!("experiment-{sequence_text}"),
            kind,
            purpose: purpose.into(),
            expected_evidence: "Operation output and bounded observations".to_owned(),
            parameters: BTreeMap::new(),
        }
    }

    pub fn validate(&self) -> Result<(), ResearchValidationError> {
        check_version(self.schema_version)?;
        validate_research_id("run_id", &self.run_id)?;
        validate_research_id("experiment_id", &self.experiment_id)?;
        if self.sequence == 0 {
            return Err(ResearchValidationError(
                "experiment sequence must be positive".to_owned(),
            ));
        }
        validate_research_text("purpose", &self.purpose)?;
        validate_research_text("expected_evidence", &self.expected_evidence)?;
        if self.parameters.len() > MAX_RESEARCH_ITEMS {
            return Err(ResearchValidationError(format!(
                "parameters exceeds {MAX_RESEARCH_ITEMS} items"
            )));
        }
        for (key, value) in &self.parameters {
            validate_research_id("parameter key", key)?;
            validate_research_text("parameter value", value)?;
        }
        Ok(())
    }
}

/// Terminal execution outcome. Rejected and failed work are not verified passes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationStatus {
    Completed,
    Rejected,
    Failed,
    BudgetExhausted,
}

/// Confidence reported by a trusted inspection or verification procedure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// A bounded, evidence-linked factual observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResearchFact {
    pub fact_id: String,
    pub statement: String,
    pub evidence_ids: Vec<String>,
    pub confidence: Confidence,
}

/// Metadata for a persisted artifact. Digests are lowercase SHA-256 hex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceArtifact {
    pub artifact_id: String,
    pub media_type: String,
    pub sha256: String,
    pub bytes: u64,
    pub source: String,
}

impl EvidenceArtifact {
    pub fn validate(&self) -> Result<(), ResearchValidationError> {
        validate_research_id("artifact_id", &self.artifact_id)?;
        validate_research_text("media_type", &self.media_type)?;
        validate_research_text("source", &self.source)?;
        if self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ResearchValidationError(
                "artifact sha256 must be 64 lowercase hexadecimal characters".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Planner-facing execution result. Artifact bytes remain outside this contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResearchObservation {
    pub schema_version: u32,
    pub run_id: String,
    pub sequence: u32,
    pub experiment_id: String,
    pub status: ObservationStatus,
    pub summary: String,
    pub facts: Vec<ResearchFact>,
    pub artifacts: Vec<EvidenceArtifact>,
    pub diagnostics: Vec<String>,
}

impl ResearchObservation {
    pub fn validate(&self) -> Result<(), ResearchValidationError> {
        check_version(self.schema_version)?;
        validate_research_id("run_id", &self.run_id)?;
        validate_research_id("experiment_id", &self.experiment_id)?;
        if self.sequence == 0 {
            return Err(ResearchValidationError(
                "observation sequence must be positive".to_owned(),
            ));
        }
        validate_research_text("summary", &self.summary)?;
        check_items("facts", &self.facts)?;
        check_items("artifacts", &self.artifacts)?;
        check_items("diagnostics", &self.diagnostics)?;
        for diagnostic in &self.diagnostics {
            validate_research_text("diagnostic", diagnostic)?;
        }
        let artifact_ids: BTreeSet<&str> = self
            .artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.as_str())
            .collect();
        if artifact_ids.len() != self.artifacts.len() {
            return Err(ResearchValidationError(
                "artifact identifiers must be unique".to_owned(),
            ));
        }
        for artifact in &self.artifacts {
            artifact.validate()?;
        }
        let fact_ids: BTreeSet<&str> = self
            .facts
            .iter()
            .map(|fact| fact.fact_id.as_str())
            .collect();
        if fact_ids.len() != self.facts.len() {
            return Err(ResearchValidationError(
                "fact identifiers must be unique".to_owned(),
            ));
        }
        for fact in &self.facts {
            validate_research_id("fact_id", &fact.fact_id)?;
            validate_research_text("fact statement", &fact.statement)?;
            check_items("fact evidence", &fact.evidence_ids)?;
            if fact.evidence_ids.is_empty() {
                return Err(ResearchValidationError(
                    "every fact must cite at least one artifact".to_owned(),
                ));
            }
            for evidence_id in &fact.evidence_ids {
                if !artifact_ids.contains(evidence_id.as_str()) {
                    return Err(ResearchValidationError(format!(
                        "fact {} references unknown artifact {evidence_id}",
                        fact.fact_id
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Whether an evaluation supports, refutes, or cannot decide its subject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvaluationStatus {
    Passed,
    Failed,
    Missing,
    NotApplicable,
}

/// Unit evaluated by an evaluation record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvaluationScope {
    Run,
    Hypothesis,
    Experiment,
}

/// Explicit per-run or per-subject evaluation, including missing coverage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    pub schema_version: u32,
    pub evaluation_id: String,
    pub scope: EvaluationScope,
    pub subject_id: String,
    pub status: EvaluationStatus,
    pub summary: String,
    pub evidence_ids: Vec<String>,
}

impl Evaluation {
    pub fn validate(&self) -> Result<(), ResearchValidationError> {
        check_version(self.schema_version)?;
        validate_research_id("evaluation_id", &self.evaluation_id)?;
        validate_research_id("subject_id", &self.subject_id)?;
        validate_research_text("evaluation summary", &self.summary)?;
        check_items("evaluation evidence", &self.evidence_ids)?;
        for evidence_id in &self.evidence_ids {
            validate_research_id("evaluation evidence id", evidence_id)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_observation() -> ResearchObservation {
        ResearchObservation {
            schema_version: RESEARCH_SCHEMA_VERSION,
            run_id: "run-1".to_owned(),
            sequence: 1,
            experiment_id: "experiment-1".to_owned(),
            status: ObservationStatus::Completed,
            summary: "Read the bounded source file".to_owned(),
            facts: vec![ResearchFact {
                fact_id: "fact-1".to_owned(),
                statement: "The file declares a public function".to_owned(),
                evidence_ids: vec!["artifact-1".to_owned()],
                confidence: Confidence::High,
            }],
            artifacts: vec![EvidenceArtifact {
                artifact_id: "artifact-1".to_owned(),
                media_type: "text/plain".to_owned(),
                sha256: "a".repeat(64),
                bytes: 20,
                source: "src/lib.rs".to_owned(),
            }],
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn repository_defaults_are_valid_and_non_mutating() {
        let manifest = TargetManifest::repository("repo", ".").unwrap();
        let policy = RunPolicy::repository_read_only();
        manifest.validate().unwrap();
        policy.validate().unwrap();
        assert_eq!(policy.authority, ResearchAuthority::ReadOnlyNetworkOff);
        assert!(policy
            .allowed_operations
            .contains(&ExperimentKind::ReadOnlyCommand));
    }

    #[test]
    fn experiment_is_proposal_data_not_an_authorization_token() {
        let experiment = ExperimentDraft::new("run-1", 1, ExperimentKind::ListFiles, "Map files");
        experiment.validate().unwrap();
        assert_eq!(experiment.schema_version, RESEARCH_SCHEMA_VERSION);
        assert_eq!(experiment.experiment_id, "experiment-1");
    }

    #[test]
    fn observation_requires_valid_digest_and_local_evidence_references() {
        let observation = valid_observation();
        observation.validate().unwrap();

        let mut bad_digest = observation.clone();
        bad_digest.artifacts[0].sha256 = "not-a-digest".to_owned();
        assert!(bad_digest.validate().is_err());

        let mut missing_evidence = observation;
        missing_evidence.facts[0].evidence_ids[0] = "unknown".to_owned();
        assert!(missing_evidence.validate().is_err());
    }

    #[test]
    fn version_and_all_resource_limits_are_checked() {
        let mut policy = RunPolicy::repository_read_only();
        policy.max_completed_experiments = policy.max_experiments + 1;
        assert!(policy.validate().is_err());

        let mut observation = valid_observation();
        observation.schema_version += 1;
        assert!(observation.validate().is_err());
    }

    #[test]
    fn duplicate_artifacts_and_paths_are_not_silently_merged() {
        let mut observation = valid_observation();
        observation.artifacts.push(observation.artifacts[0].clone());
        assert!(observation.validate().is_err());
    }
}
