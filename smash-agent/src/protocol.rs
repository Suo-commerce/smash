//! Versioned planner protocol and strict bounded-JSON decoding.

use serde::{Deserialize, Serialize};
use smash_core::research::{
    Confidence, Evaluation, EvaluationScope, EvaluationStatus, ExperimentDraft, ExperimentKind,
    ResearchObservation, TargetManifest, RESEARCH_SCHEMA_VERSION,
};
use std::collections::BTreeSet;
use std::fmt;

pub const MAX_PLANNER_RESPONSE_BYTES: usize = 256 * 1024;
pub const MAX_PLANNER_CONTEXT_OBSERVATIONS: usize = 256;

/// Everything a planner may observe. There is no execution handle in this type.
#[derive(Clone, Debug)]
pub struct PlannerContext<'a> {
    pub run_id: &'a str,
    pub next_sequence: u32,
    pub target: &'a TargetManifest,
    pub observations: &'a [ResearchObservation],
}

/// A falsifiable engineering statement. It is never a security classification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisDraft {
    pub hypothesis_id: String,
    pub statement: String,
    pub status: HypothesisStatus,
    pub evidence_ids: Vec<String>,
    pub falsification_test: String,
    pub confidence: ConfidenceWire,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisStatus {
    Open,
    Supported,
    Refuted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceWire {
    High,
    Medium,
    Low,
}

impl From<ConfidenceWire> for Confidence {
    fn from(value: ConfidenceWire) -> Self {
        match value {
            ConfidenceWire::High => Confidence::High,
            ConfidenceWire::Medium => Confidence::Medium,
            ConfidenceWire::Low => Confidence::Low,
        }
    }
}

/// Planner-requested campaign completion, including explicit missing coverage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletionDraft {
    pub summary: String,
    pub hypotheses: Vec<HypothesisDraft>,
    pub evaluations: Vec<Evaluation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentAction {
    NextExperiment(ExperimentDraft),
    Complete(CompletionDraft),
}

/// The single typed decision obtained from exactly one provider response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannerOutput {
    pub action: AgentAction,
    pub response_sha256: String,
}

pub trait Planner {
    fn next_experiment(
        &mut self,
        context: &PlannerContext<'_>,
    ) -> Result<PlannerOutput, PlannerError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannerError(pub String);

impl fmt::Display for PlannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PlannerError {}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum WireResponse {
    Experiment {
        schema_version: u32,
        experiment: WireExperiment,
    },
    Complete {
        schema_version: u32,
        summary: String,
        hypotheses: Vec<HypothesisDraft>,
        evaluations: Vec<WireEvaluation>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireExperiment {
    schema_version: u32,
    experiment_id: String,
    kind: WireExperimentKind,
    purpose: String,
    expected_evidence: String,
    #[serde(default)]
    parameters: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireExperimentKind {
    ListFiles,
    ReadFile,
    ReadManifest,
    WorkingTreeStatus,
    ReadOnlyCommand,
}

impl From<WireExperimentKind> for ExperimentKind {
    fn from(value: WireExperimentKind) -> Self {
        match value {
            WireExperimentKind::ListFiles => ExperimentKind::ListFiles,
            WireExperimentKind::ReadFile => ExperimentKind::ReadFile,
            WireExperimentKind::ReadManifest => ExperimentKind::ReadManifest,
            WireExperimentKind::WorkingTreeStatus => ExperimentKind::WorkingTreeStatus,
            WireExperimentKind::ReadOnlyCommand => ExperimentKind::ReadOnlyCommand,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEvaluation {
    evaluation_id: String,
    scope: WireEvaluationScope,
    subject_id: String,
    status: WireEvaluationStatus,
    summary: String,
    #[serde(default)]
    evidence_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireEvaluationScope {
    Run,
    Hypothesis,
    Experiment,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireEvaluationStatus {
    Passed,
    Failed,
    Missing,
    NotApplicable,
}

/// Decode one complete response. Unknown fields, trailing JSON, invalid UTF-8,
/// unsupported versions, excessive bytes, and stale run/sequence IDs are errors.
pub fn decode_response(
    bytes: &[u8],
    context: &PlannerContext<'_>,
) -> Result<AgentAction, PlannerError> {
    if bytes.len() > MAX_PLANNER_RESPONSE_BYTES {
        return Err(PlannerError(format!(
            "planner response exceeds {MAX_PLANNER_RESPONSE_BYTES} bytes"
        )));
    }
    std::str::from_utf8(bytes)
        .map_err(|error| PlannerError(format!("planner response is not UTF-8: {error}")))?;
    if context.next_sequence == 0 || context.observations.len() > MAX_PLANNER_CONTEXT_OBSERVATIONS {
        return Err(PlannerError("invalid planner context bounds".to_owned()));
    }
    context
        .target
        .validate()
        .map_err(|error| PlannerError(error.to_string()))?;
    for (index, observation) in context.observations.iter().enumerate() {
        observation
            .validate()
            .map_err(|error| PlannerError(format!("invalid context observation: {error}")))?;
        if observation.run_id != context.run_id || observation.sequence as usize != index + 1 {
            return Err(PlannerError(
                "context observations are not a contiguous run history".to_owned(),
            ));
        }
    }

    let response: WireResponse = serde_json::from_slice(bytes)
        .map_err(|error| PlannerError(format!("invalid planner JSON: {error}")))?;
    let known_evidence: BTreeSet<&str> = context
        .observations
        .iter()
        .flat_map(|observation| observation.artifacts.iter())
        .map(|artifact| artifact.artifact_id.as_str())
        .collect();

    match response {
        WireResponse::Experiment {
            schema_version,
            experiment,
        } => {
            if schema_version != RESEARCH_SCHEMA_VERSION {
                return Err(PlannerError("unsupported planner schema".to_owned()));
            }
            if experiment.schema_version != RESEARCH_SCHEMA_VERSION {
                return Err(PlannerError("unsupported experiment schema".to_owned()));
            }
            let draft = ExperimentDraft {
                schema_version: experiment.schema_version,
                run_id: context.run_id.to_owned(),
                sequence: context.next_sequence,
                experiment_id: experiment.experiment_id,
                kind: experiment.kind.into(),
                purpose: experiment.purpose,
                expected_evidence: experiment.expected_evidence,
                parameters: experiment.parameters,
            };
            draft
                .validate()
                .map_err(|error| PlannerError(error.to_string()))?;
            Ok(AgentAction::NextExperiment(draft))
        }
        WireResponse::Complete {
            schema_version,
            summary,
            hypotheses,
            evaluations,
        } => {
            if schema_version != RESEARCH_SCHEMA_VERSION {
                return Err(PlannerError("unsupported planner schema".to_owned()));
            }
            smash_core::research::validate_research_text("completion summary", &summary)
                .map_err(|error| PlannerError(error.to_string()))?;
            validate_hypotheses(&hypotheses, &known_evidence)?;
            if evaluations.len() > smash_core::research::MAX_RESEARCH_ITEMS {
                return Err(PlannerError("too many evaluations".to_owned()));
            }
            let hypothesis_ids: BTreeSet<&str> = hypotheses
                .iter()
                .map(|hypothesis| hypothesis.hypothesis_id.as_str())
                .collect();
            let experiment_ids: BTreeSet<&str> = context
                .observations
                .iter()
                .map(|observation| observation.experiment_id.as_str())
                .collect();
            let mut evaluation_ids = BTreeSet::new();
            let mut converted = Vec::with_capacity(evaluations.len());
            for evaluation in evaluations {
                let evaluation = Evaluation {
                    schema_version: RESEARCH_SCHEMA_VERSION,
                    evaluation_id: evaluation.evaluation_id,
                    scope: match evaluation.scope {
                        WireEvaluationScope::Run => smash_core::research::EvaluationScope::Run,
                        WireEvaluationScope::Hypothesis => {
                            smash_core::research::EvaluationScope::Hypothesis
                        }
                        WireEvaluationScope::Experiment => {
                            smash_core::research::EvaluationScope::Experiment
                        }
                    },
                    subject_id: evaluation.subject_id,
                    status: match evaluation.status {
                        WireEvaluationStatus::Passed => {
                            smash_core::research::EvaluationStatus::Passed
                        }
                        WireEvaluationStatus::Failed => {
                            smash_core::research::EvaluationStatus::Failed
                        }
                        WireEvaluationStatus::Missing => {
                            smash_core::research::EvaluationStatus::Missing
                        }
                        WireEvaluationStatus::NotApplicable => {
                            smash_core::research::EvaluationStatus::NotApplicable
                        }
                    },
                    summary: evaluation.summary,
                    evidence_ids: evaluation.evidence_ids,
                };
                evaluation
                    .validate()
                    .map_err(|error| PlannerError(error.to_string()))?;
                if !evaluation_ids.insert(evaluation.evaluation_id.clone())
                    || reserved_evaluation_id(&evaluation.evaluation_id)
                {
                    return Err(PlannerError(
                        "duplicate or reserved evaluation identifier".to_owned(),
                    ));
                }
                let known_subject = match evaluation.scope {
                    EvaluationScope::Run => evaluation.subject_id == context.run_id,
                    EvaluationScope::Hypothesis => {
                        hypothesis_ids.contains(evaluation.subject_id.as_str())
                    }
                    EvaluationScope::Experiment => {
                        experiment_ids.contains(evaluation.subject_id.as_str())
                    }
                };
                if !known_subject {
                    return Err(PlannerError(
                        "evaluation does not reference a subject in this campaign".to_owned(),
                    ));
                }
                if evaluation.status == EvaluationStatus::Passed
                    && evaluation.evidence_ids.is_empty()
                {
                    return Err(PlannerError(
                        "a passing evaluation requires evidence".to_owned(),
                    ));
                }
                if evaluation
                    .evidence_ids
                    .iter()
                    .any(|id| !known_evidence.contains(id.as_str()))
                {
                    return Err(PlannerError(
                        "evaluation references unknown evidence".to_owned(),
                    ));
                }
                converted.push(evaluation);
            }
            Ok(AgentAction::Complete(CompletionDraft {
                summary,
                hypotheses,
                evaluations: converted,
            }))
        }
    }
}

pub(crate) fn reserved_evaluation_id(id: &str) -> bool {
    id.starts_with("run:") || id.starts_with("coverage:") || id.starts_with("evaluation:")
}

fn validate_hypotheses(
    hypotheses: &[HypothesisDraft],
    known_evidence: &BTreeSet<&str>,
) -> Result<(), PlannerError> {
    if hypotheses.len() > smash_core::research::MAX_RESEARCH_ITEMS {
        return Err(PlannerError("too many hypotheses".to_owned()));
    }
    let mut ids = BTreeSet::new();
    for hypothesis in hypotheses {
        smash_core::research::validate_research_id("hypothesis_id", &hypothesis.hypothesis_id)
            .and_then(|_| {
                smash_core::research::validate_research_text(
                    "hypothesis statement",
                    &hypothesis.statement,
                )
            })
            .and_then(|_| {
                smash_core::research::validate_research_text(
                    "hypothesis falsification test",
                    &hypothesis.falsification_test,
                )
            })
            .map_err(|error| PlannerError(error.to_string()))?;
        if !ids.insert(&hypothesis.hypothesis_id) {
            return Err(PlannerError("duplicate hypothesis".to_owned()));
        }
        if hypothesis.evidence_ids.len() > smash_core::research::MAX_RESEARCH_ITEMS
            || hypothesis
                .evidence_ids
                .iter()
                .any(|id| !known_evidence.contains(id.as_str()))
        {
            return Err(PlannerError(
                "hypothesis references unknown evidence".to_owned(),
            ));
        }
        if hypothesis.status != HypothesisStatus::Open && hypothesis.evidence_ids.is_empty() {
            return Err(PlannerError(
                "decided hypotheses require evidence".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scripted::ScriptedPlanner;
    use smash_core::research::{ObservationStatus, ResearchObservation};

    fn context<'a>(observations: &'a [ResearchObservation]) -> PlannerContext<'a> {
        // The target lives for the test statement, just like a real run target.
        PlannerContext {
            run_id: "run-1",
            next_sequence: observations.len() as u32 + 1,
            target: Box::leak(Box::new(TargetManifest::repository("repo", ".").unwrap())),
            observations,
        }
    }

    fn experiment_json() -> String {
        r#"{
            "schema_version":1,
            "action":"experiment",
            "experiment":{
                "schema_version":1,
                "experiment_id":"experiment-1",
                "kind":"list_files",
                "purpose":"Map the repository",
                "expected_evidence":"A bounded path listing",
                "parameters":{}
            }
        }"#
        .to_owned()
    }

    #[test]
    fn strict_experiment_decoding_injects_run_and_sequence() {
        let context = context(&[]);
        let action = decode_response(experiment_json().as_bytes(), &context).unwrap();
        let AgentAction::NextExperiment(draft) = action else {
            panic!("expected experiment")
        };
        assert_eq!(draft.run_id, "run-1");
        assert_eq!(draft.sequence, 1);
        assert_eq!(draft.kind, ExperimentKind::ListFiles);
    }

    #[test]
    fn unknown_fields_invalid_utf8_and_trailing_json_are_rejected() {
        let context = context(&[]);
        let unknown = experiment_json().replace("\"purpose\"", "\"unexpected\":true,\"purpose\"");
        assert!(decode_response(unknown.as_bytes(), &context).is_err());
        assert!(decode_response(&[0xff], &context).is_err());
        assert!(
            decode_response(format!("{} {{}}", experiment_json()).as_bytes(), &context).is_err()
        );
    }

    #[test]
    fn unsupported_schema_and_oversized_responses_are_rejected() {
        let context = context(&[]);
        assert!(decode_response(
            experiment_json()
                .replace("\"schema_version\":1", "\"schema_version\":2")
                .as_bytes(),
            &context
        )
        .is_err());
        assert!(decode_response(&vec![b' '; MAX_PLANNER_RESPONSE_BYTES + 1], &context).is_err());
    }

    #[test]
    fn supported_hypotheses_cannot_cite_unknown_evidence() {
        let context = context(&[]);
        let response = r#"{
            "schema_version":1,
            "action":"complete",
            "summary":"Inspection complete with bounded coverage",
            "hypotheses":[{
                "hypothesis_id":"h1",
                "statement":"The crate uses SHA-256",
                "status":"supported",
                "evidence_ids":["not-observed"],
                "falsification_test":"Inspect the hashing import",
                "confidence":"high"
            }],
            "evaluations":[]
        }"#;
        assert!(decode_response(response.as_bytes(), &context).is_err());
    }

    #[test]
    fn open_hypothesis_and_missing_evaluation_survive_without_evidence() {
        let context = context(&[]);
        let response = r#"{
            "schema_version":1,
            "action":"complete",
            "summary":"Only the manifest was inspected; runtime behavior is unknown",
            "hypotheses":[{
                "hypothesis_id":"h1",
                "statement":"The CLI dispatches commands",
                "status":"open",
                "evidence_ids":[],
                "falsification_test":"Inspect the CLI process declarations",
                "confidence":"low"
            }],
            "evaluations":[{
                "evaluation_id":"coverage-runtime",
                "scope":"run",
                "subject_id":"run-1",
                "status":"missing",
                "summary":"No runtime test was executed",
                "evidence_ids":[]
            }]
        }"#;
        let AgentAction::Complete(completion) =
            decode_response(response.as_bytes(), &context).unwrap()
        else {
            panic!("expected completion")
        };
        assert_eq!(completion.hypotheses.len(), 1);
        assert_eq!(
            completion.evaluations[0].status,
            smash_core::research::EvaluationStatus::Missing
        );
    }

    #[test]
    fn scripted_planner_consumes_exactly_one_response_and_never_retries() {
        let context = context(&[]);
        let mut planner = ScriptedPlanner::from_json([experiment_json()]);
        let first = planner.next_experiment(&context).unwrap();
        assert_eq!(planner.decisions, 1);
        assert_eq!(planner.remaining(), 0);
        assert_eq!(first.response_sha256.len(), 64);
        assert!(planner.next_experiment(&context).is_err());
        assert_eq!(planner.decisions, 1);
    }

    #[test]
    fn noncontiguous_observation_history_is_rejected() {
        let observation = ResearchObservation {
            schema_version: RESEARCH_SCHEMA_VERSION,
            run_id: "run-1".to_owned(),
            sequence: 2,
            experiment_id: "experiment-2".to_owned(),
            status: ObservationStatus::Completed,
            summary: "An out-of-order observation".to_owned(),
            facts: vec![],
            artifacts: vec![],
            diagnostics: vec![],
        };
        let observations = [observation];
        let context = context(&observations);
        assert!(decode_response(experiment_json().as_bytes(), &context).is_err());
    }

    #[test]
    fn zero_evidence_passes_unknown_subjects_and_reserved_ids_are_rejected() {
        let response = |id: &str, subject: &str, status: &str| {
            format!(
                r#"{{"schema_version":1,"action":"complete","summary":"Bounded completion with no evidence","hypotheses":[],"evaluations":[{{"evaluation_id":"{id}","scope":"run","subject_id":"{subject}","status":"{status}","summary":"Planner evaluation","evidence_ids":[]}}]}}"#
            )
        };
        let context = context(&[]);
        assert!(decode_response(
            response("planner-pass", "run-1", "passed").as_bytes(),
            &context
        )
        .is_err());
        assert!(decode_response(
            response("unknown-run", "run-2", "missing").as_bytes(),
            &context
        )
        .is_err());
        for id in ["run:bounded-recon", "coverage:runtime", "evaluation:h1"] {
            assert!(
                decode_response(response(id, "run-1", "missing").as_bytes(), &context).is_err()
            );
        }
    }
}
