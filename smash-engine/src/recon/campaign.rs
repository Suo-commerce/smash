//! Bounded campaign runner: planner proposals in, admitted observations out.

use super::repository::RepositoryInspector;
use serde::{Deserialize, Serialize};
use smash_agent::protocol::{
    AgentAction, CompletionDraft, HypothesisStatus, Planner, PlannerContext,
};
use smash_core::research::{
    Evaluation, EvaluationScope, EvaluationStatus, ExperimentDraft, ObservationStatus,
    ResearchObservation, RunPolicy, TargetManifest, RESEARCH_SCHEMA_VERSION,
    TERMINAL_OBSERVATION_RESERVE_BYTES,
};
use std::collections::BTreeMap;
use std::time::Instant;

// Re-export the agent hypothesis shape for bundle/report consumers.
pub use smash_agent::protocol::HypothesisDraft;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStatus {
    Completed,
    BudgetExhausted,
    PlannerFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRecord {
    pub provider: String,
    pub model: String,
    pub version: String,
    pub prompt_template_version: String,
    pub queries: u32,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cost_microusd: Option<u64>,
}

impl ProviderRecord {
    pub fn scripted(prompt_template_version: impl Into<String>) -> Self {
        Self {
            provider: "scripted".to_owned(),
            model: "none".to_owned(),
            version: "1".to_owned(),
            prompt_template_version: prompt_template_version.into(),
            queries: 0,
            input_tokens: None,
            output_tokens: None,
            cost_microusd: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProposalRecord {
    pub draft: ExperimentDraft,
    pub observation: ResearchObservation,
    pub response_sha256: String,
}

#[derive(Clone, Debug)]
pub struct Campaign {
    pub run_id: String,
    pub target: TargetManifest,
    pub policy: RunPolicy,
    pub status: CampaignStatus,
    pub summary: String,
    pub provider: ProviderRecord,
    pub proposals: Vec<ProposalRecord>,
    pub hypotheses: Vec<HypothesisDraft>,
    pub evaluations: Vec<Evaluation>,
    pub artifacts: BTreeMap<String, Vec<u8>>,
    pub diagnostics: Vec<String>,
    pub elapsed_milliseconds: u64,
}

#[derive(Clone, Debug)]
pub struct CampaignRunner {
    run_id: String,
    target: TargetManifest,
    policy: RunPolicy,
    provider: ProviderRecord,
}

impl CampaignRunner {
    pub fn new(
        run_id: impl Into<String>,
        target: TargetManifest,
        policy: RunPolicy,
        provider: ProviderRecord,
    ) -> Result<Self, String> {
        let run_id = run_id.into();
        if run_id.is_empty()
            || run_id.len() > 128
            || !run_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err("invalid campaign run identifier".to_owned());
        }
        target.validate().map_err(|error| error.to_string())?;
        policy.validate().map_err(|error| error.to_string())?;
        Ok(Self {
            run_id,
            target,
            policy,
            provider,
        })
    }

    pub fn run<P: Planner, I: RepositoryInspector>(
        self,
        planner: &mut P,
        inspector: &mut I,
    ) -> Campaign {
        let started = Instant::now();
        let mut campaign = Campaign {
            run_id: self.run_id.clone(),
            target: self.target,
            policy: self.policy.clone(),
            status: CampaignStatus::Completed,
            summary: "Campaign ended without a completion decision".to_owned(),
            provider: self.provider,
            proposals: Vec::new(),
            hypotheses: Vec::new(),
            evaluations: Vec::new(),
            artifacts: BTreeMap::new(),
            diagnostics: Vec::new(),
            elapsed_milliseconds: 0,
        };
        let mut observations = Vec::new();
        let mut total_observation_bytes = 0u64;
        let mut total_evidence_bytes = 0u64;
        // Rejections consume experiment slots. Reserving against the completed cap
        // too is conservative and ensures an effect can never overrun that cap.
        let experiment_limit = self
            .policy
            .max_experiments
            .min(self.policy.max_completed_experiments);

        loop {
            campaign.elapsed_milliseconds = started.elapsed().as_millis() as u64;
            if campaign.elapsed_milliseconds
                >= self.policy.max_wall_time_seconds.saturating_mul(1000)
            {
                campaign.status = CampaignStatus::BudgetExhausted;
                campaign.summary = "Wall-time budget exhausted before completion".to_owned();
                campaign
                    .diagnostics
                    .push("wall-time ceiling reached".to_owned());
                break;
            }
            if campaign.provider.queries >= self.policy.max_queries
                || observations.len() >= experiment_limit as usize
            {
                campaign.status = CampaignStatus::BudgetExhausted;
                campaign.summary =
                    "Query or experiment budget exhausted before completion".to_owned();
                campaign
                    .diagnostics
                    .push("planner/experiment ceiling reached".to_owned());
                break;
            }

            let context = PlannerContext {
                run_id: &campaign.run_id,
                next_sequence: observations.len() as u32 + 1,
                target: &campaign.target,
                observations: &observations,
            };
            campaign.provider.queries += 1;
            let output = match planner.next_experiment(&context) {
                Ok(output) => output,
                Err(error) => {
                    campaign.status = CampaignStatus::PlannerFailed;
                    campaign.summary = "Planner failed closed without further execution".to_owned();
                    campaign.diagnostics.push(format!("planner error: {error}"));
                    break;
                }
            };
            match output.action {
                AgentAction::Complete(completion) => {
                    campaign.status = CampaignStatus::Completed;
                    complete_campaign(&mut campaign, completion);
                    break;
                }
                AgentAction::NextExperiment(draft) => {
                    let inspection = inspector.inspect(&draft, &self.policy);
                    let observation = inspection.observation;
                    if let Err(error) = observation.validate() {
                        campaign.status = CampaignStatus::PlannerFailed;
                        campaign.summary =
                            "Executor produced an invalid observation; campaign stopped".to_owned();
                        campaign.diagnostics.push(error.to_string());
                        break;
                    }
                    let observation_bytes = super::bundle::campaign_observation_size(&observation);
                    let candidate_evidence_bytes: u64 = inspection
                        .contents
                        .iter()
                        .map(|(_, content)| content.len() as u64)
                        .sum();
                    let artifact_too_large = inspection
                        .contents
                        .iter()
                        .any(|(_, content)| content.len() as u64 > self.policy.max_artifact_bytes);
                    let observation_total_ceiling = self
                        .policy
                        .max_total_observation_bytes
                        .saturating_sub(TERMINAL_OBSERVATION_RESERVE_BYTES);
                    let observation_memory_ceiling = self
                        .policy
                        .max_observations_memory_bytes
                        .saturating_sub(TERMINAL_OBSERVATION_RESERVE_BYTES);
                    if observation_bytes > self.policy.max_observation_bytes
                        || total_observation_bytes.saturating_add(observation_bytes)
                            > observation_total_ceiling
                        || total_observation_bytes.saturating_add(observation_bytes)
                            > observation_memory_ceiling
                        || artifact_too_large
                        || total_evidence_bytes.saturating_add(candidate_evidence_bytes)
                            > self.policy.max_total_evidence_bytes
                    {
                        let rejected = ResearchObservation {
                            schema_version: RESEARCH_SCHEMA_VERSION,
                            run_id: campaign.run_id.clone(),
                            sequence: draft.sequence,
                            experiment_id: draft.experiment_id.clone(),
                            status: ObservationStatus::BudgetExhausted,
                            summary: "Observation or evidence budget exhausted".to_owned(),
                            facts: vec![],
                            artifacts: vec![],
                            diagnostics: vec![
                                "captured data was discarded rather than exceeding a hard limit"
                                    .to_owned(),
                            ],
                        };
                        let rejected_bytes = super::bundle::campaign_observation_size(&rejected);
                        if rejected_bytes > self.policy.max_observation_bytes
                            || total_observation_bytes.saturating_add(rejected_bytes)
                                > self.policy.max_total_observation_bytes
                            || total_observation_bytes.saturating_add(rejected_bytes)
                                > self.policy.max_observations_memory_bytes
                        {
                            campaign.status = CampaignStatus::PlannerFailed;
                            campaign.summary =
                                "Terminal budget observation did not fit its reserve".to_owned();
                            break;
                        }
                        observations.push(rejected.clone());
                        campaign.proposals.push(ProposalRecord {
                            draft,
                            observation: rejected,
                            response_sha256: output.response_sha256,
                        });
                        campaign.status = CampaignStatus::BudgetExhausted;
                        campaign.summary = "Evidence budget exhausted before completion".to_owned();
                        break;
                    }
                    total_observation_bytes += observation_bytes;
                    total_evidence_bytes += candidate_evidence_bytes;
                    for (id, content) in inspection.contents {
                        if campaign.artifacts.insert(id, content).is_some() {
                            campaign.status = CampaignStatus::PlannerFailed;
                            campaign.summary =
                                "Duplicate artifact identity stopped the campaign".to_owned();
                            campaign
                                .diagnostics
                                .push("executor reused an artifact ID".to_owned());
                            campaign.elapsed_milliseconds = started.elapsed().as_millis() as u64;
                            return campaign;
                        }
                    }
                    observations.push(observation.clone());
                    campaign.proposals.push(ProposalRecord {
                        draft,
                        observation,
                        response_sha256: output.response_sha256,
                    });
                }
            }
        }
        if campaign.status != CampaignStatus::Completed {
            ensure_missing_coverage(&mut campaign);
        }
        campaign.elapsed_milliseconds = started.elapsed().as_millis() as u64;
        campaign
    }
}

fn complete_campaign(campaign: &mut Campaign, completion: CompletionDraft) {
    campaign.summary = completion.summary;
    campaign.hypotheses = completion.hypotheses;
    campaign.evaluations = completion.evaluations;
    if !campaign.evaluations.iter().any(|evaluation| {
        evaluation.scope == EvaluationScope::Run && evaluation.subject_id == campaign.run_id
    }) {
        campaign.evaluations.push(Evaluation {
            schema_version: RESEARCH_SCHEMA_VERSION,
            evaluation_id: "run:bounded-recon".to_owned(),
            scope: EvaluationScope::Run,
            subject_id: campaign.run_id.clone(),
            status: if campaign.proposals.iter().any(|proposal| {
                proposal.observation.status == ObservationStatus::Completed
            }) {
                EvaluationStatus::Passed
            } else {
                EvaluationStatus::Missing
            },
            summary: "Bounded source observations were evaluated; exhaustive and dynamic verification remain separate".to_owned(),
            evidence_ids: campaign.proposals.iter().flat_map(|proposal| {
                proposal.observation.artifacts.iter().map(|artifact| artifact.artifact_id.clone())
            }).collect(),
        });
    }
    for hypothesis in &campaign.hypotheses {
        if campaign.evaluations.iter().any(|evaluation| {
            evaluation.scope == EvaluationScope::Hypothesis
                && evaluation.subject_id == hypothesis.hypothesis_id
        }) {
            continue;
        }
        campaign.evaluations.push(Evaluation {
            schema_version: RESEARCH_SCHEMA_VERSION,
            evaluation_id: format!("evaluation:{}", hypothesis.hypothesis_id),
            scope: EvaluationScope::Hypothesis,
            subject_id: hypothesis.hypothesis_id.clone(),
            status: match hypothesis.status {
                HypothesisStatus::Open => EvaluationStatus::Missing,
                HypothesisStatus::Supported | HypothesisStatus::Refuted => EvaluationStatus::Passed,
            },
            summary: match hypothesis.status {
                HypothesisStatus::Open => {
                    "Hypothesis has insufficient evidence for a decision".to_owned()
                }
                HypothesisStatus::Supported => {
                    "Source-observed support only; no dynamic vulnerability verification".to_owned()
                }
                HypothesisStatus::Refuted => {
                    "Recorded source evidence refutes this engineering hypothesis".to_owned()
                }
            },
            evidence_ids: hypothesis.evidence_ids.clone(),
        });
    }
    if campaign.proposals.is_empty()
        || campaign
            .proposals
            .iter()
            .all(|proposal| proposal.observation.status != ObservationStatus::Completed)
    {
        ensure_missing_coverage(campaign);
    }
}

fn ensure_missing_coverage(campaign: &mut Campaign) {
    if campaign.evaluations.iter().any(|evaluation| {
        evaluation.scope == EvaluationScope::Run && evaluation.subject_id == campaign.run_id
    }) {
        return;
    }
    campaign.evaluations.push(Evaluation {
        schema_version: RESEARCH_SCHEMA_VERSION,
        evaluation_id: "coverage:repository-reconnaissance".to_owned(),
        scope: EvaluationScope::Run,
        subject_id: campaign.run_id.clone(),
        status: EvaluationStatus::Missing,
        summary: "Complete repository or runtime coverage was not established; no security pass is claimed".to_owned(),
        evidence_ids: vec![],
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recon::repository::{Inspection, ReadOnlyRepository};
    use smash_agent::ScriptedPlanner;
    use smash_core::research::{Confidence, EvidenceArtifact, ExperimentKind, ResearchFact};

    fn policy() -> RunPolicy {
        RunPolicy::repository_read_only()
    }

    fn experiment() -> String {
        r#"{"schema_version":1,"action":"experiment","experiment":{"schema_version":1,"experiment_id":"experiment-1","kind":"read_file","purpose":"Inspect source","expected_evidence":"Source excerpt","parameters":{"path":"src/lib.rs"}}}"#.to_owned()
    }

    fn complete() -> String {
        r#"{"schema_version":1,"action":"complete","summary":"One bounded source file inspected; runtime untested","hypotheses":[{"hypothesis_id":"h-source","statement":"The parser delegates directly to an interpreter","status":"supported","evidence_ids":["artifact-1-1"],"falsification_test":"Show the validation boundary before the interpreter","confidence":"medium"}],"evaluations":[]}"#.to_owned()
    }

    fn completed_run() -> Campaign {
        let root = std::env::temp_dir().join(format!("smash-campaign-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/lib.rs"),
            "pub fn parse(input: &str) { interpret(input); }",
        )
        .unwrap();
        let target = TargetManifest::repository("repo", root.to_str().unwrap()).unwrap();
        let mut planner = ScriptedPlanner::from_json([experiment(), complete()]);
        let mut inspector = ReadOnlyRepository::open(&target).unwrap();
        let campaign = CampaignRunner::new(
            "run-1",
            target,
            policy(),
            ProviderRecord::scripted("tests/v1"),
        )
        .unwrap()
        .run(&mut planner, &mut inspector);
        std::fs::remove_dir_all(root).unwrap();
        campaign
    }

    #[test]
    fn completed_campaign_binds_source_hypothesis_to_artifact_and_has_run_evaluation() {
        let campaign = completed_run();
        assert_eq!(campaign.status, CampaignStatus::Completed);
        assert_eq!(campaign.proposals.len(), 1);
        assert_eq!(campaign.hypotheses[0].evidence_ids, ["artifact-1-1"]);
        assert!(campaign.evaluations.iter().any(|evaluation| {
            evaluation.scope == EvaluationScope::Hypothesis
                && evaluation.subject_id == "h-source"
                && evaluation.status == EvaluationStatus::Passed
        }));
        assert!(campaign.evaluations.iter().any(|evaluation| {
            evaluation.scope == EvaluationScope::Run
                && evaluation.status == EvaluationStatus::Passed
        }));
    }

    #[test]
    fn malformed_planner_is_recorded_as_operational_failure_not_success() {
        let target = TargetManifest::repository("repo", ".").unwrap();
        let mut planner = ScriptedPlanner::from_json(["not-json"]);
        let mut inspector = UnusedInspector;
        let campaign = CampaignRunner::new(
            "run-1",
            target,
            policy(),
            ProviderRecord::scripted("tests/v1"),
        )
        .unwrap()
        .run(&mut planner, &mut inspector);
        assert_eq!(campaign.status, CampaignStatus::PlannerFailed);
        assert!(campaign.proposals.is_empty());
        assert_eq!(campaign.evaluations[0].status, EvaluationStatus::Missing);
    }

    #[test]
    fn exhausted_script_does_not_spin_or_execute_another_operation() {
        let target = TargetManifest::repository("repo", ".").unwrap();
        let mut planner = ScriptedPlanner::from_json([experiment()]);
        let mut inspector = StubInspector;
        let campaign = CampaignRunner::new(
            "run-1",
            target,
            policy(),
            ProviderRecord::scripted("tests/v1"),
        )
        .unwrap()
        .run(&mut planner, &mut inspector);
        assert_eq!(campaign.status, CampaignStatus::PlannerFailed);
        assert_eq!(campaign.provider.queries, 2);
        assert_eq!(campaign.proposals.len(), 1);
    }

    #[test]
    fn experiment_budget_is_a_hard_stop_before_another_planner_query() {
        let target = TargetManifest::repository("repo", ".").unwrap();
        let mut limited = policy();
        limited.max_experiments = 1;
        limited.max_completed_experiments = 1;
        let mut planner = ScriptedPlanner::from_json([experiment()]);
        let mut inspector = StubInspector;
        let campaign = CampaignRunner::new(
            "run-1",
            target,
            limited,
            ProviderRecord::scripted("tests/v1"),
        )
        .unwrap()
        .run(&mut planner, &mut inspector);
        assert_eq!(campaign.status, CampaignStatus::BudgetExhausted);
        assert_eq!(campaign.provider.queries, 1);
        assert_eq!(campaign.proposals.len(), 1);
        assert_eq!(campaign.evaluations[0].status, EvaluationStatus::Missing);
    }

    #[test]
    fn oversized_observation_is_replaced_without_exceeding_persisted_budget() {
        let target = TargetManifest::repository("repo", ".").unwrap();
        let mut limited = policy();
        limited.max_observation_bytes = 2048;
        limited.max_total_observation_bytes = 2048;
        limited.max_observations_memory_bytes = 2048;
        let mut planner = ScriptedPlanner::from_json([experiment()]);
        let mut inspector = LargeInspector;
        let campaign = CampaignRunner::new(
            "run-1",
            target,
            limited.clone(),
            ProviderRecord::scripted("tests/v1"),
        )
        .unwrap()
        .run(&mut planner, &mut inspector);
        assert_eq!(campaign.status, CampaignStatus::BudgetExhausted);
        assert_eq!(campaign.proposals.len(), 1);
        assert_eq!(
            campaign.proposals[0].observation.status,
            ObservationStatus::BudgetExhausted
        );
        let encoded =
            super::super::bundle::campaign_observation_size(&campaign.proposals[0].observation);
        assert!(encoded <= limited.max_observation_bytes);
        assert!(encoded <= limited.max_total_observation_bytes);
        assert!(campaign.artifacts.is_empty());
    }

    struct LargeInspector;
    impl RepositoryInspector for LargeInspector {
        fn inspect(&mut self, draft: &ExperimentDraft, _: &RunPolicy) -> Inspection {
            Inspection {
                observation: ResearchObservation {
                    schema_version: RESEARCH_SCHEMA_VERSION,
                    run_id: draft.run_id.clone(),
                    sequence: draft.sequence,
                    experiment_id: draft.experiment_id.clone(),
                    status: ObservationStatus::Completed,
                    summary: "too large ".repeat(1000),
                    facts: vec![],
                    artifacts: vec![],
                    diagnostics: vec![],
                },
                contents: vec![],
            }
        }
    }

    struct UnusedInspector;
    impl RepositoryInspector for UnusedInspector {
        fn inspect(&mut self, _: &ExperimentDraft, _: &RunPolicy) -> Inspection {
            panic!("malformed planner must not execute")
        }
    }

    struct StubInspector;
    impl RepositoryInspector for StubInspector {
        fn inspect(&mut self, draft: &ExperimentDraft, _: &RunPolicy) -> Inspection {
            assert_eq!(draft.kind, ExperimentKind::ReadFile);
            let artifact = EvidenceArtifact {
                artifact_id: "artifact-1-1".to_owned(),
                media_type: "text/plain".to_owned(),
                sha256: "a".repeat(64),
                bytes: 6,
                source: "src/lib.rs".to_owned(),
            };
            Inspection {
                observation: ResearchObservation {
                    schema_version: RESEARCH_SCHEMA_VERSION,
                    run_id: draft.run_id.clone(),
                    sequence: draft.sequence,
                    experiment_id: draft.experiment_id.clone(),
                    status: ObservationStatus::Completed,
                    summary: "Source inspected".to_owned(),
                    facts: vec![ResearchFact {
                        fact_id: "fact-1-1".to_owned(),
                        statement: "A bounded source statement".to_owned(),
                        evidence_ids: vec![artifact.artifact_id.clone()],
                        confidence: Confidence::High,
                    }],
                    artifacts: vec![artifact],
                    diagnostics: vec![],
                },
                contents: vec![("artifact-1-1".to_owned(), b"source".to_vec())],
            }
        }
    }
}
