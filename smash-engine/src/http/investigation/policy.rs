use crate::http::campaign::{HttpCampaignError, HttpCampaignPolicy};
use crate::http::policy::OperationEffect;
use crate::recon::VerifiedReconBundle;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use smash_agent::investigation::{
    validate_investigation_context, CallDescriptor, Hypothesis, HypothesisStatus,
    InvestigationContext, QueueItem, QueueStatus, Usage, INVESTIGATION_SCHEMA_VERSION,
    MAX_INVESTIGATION_CALLS, MAX_INVESTIGATION_ITEMS,
};
use std::collections::{BTreeMap, BTreeSet};

pub const M4_INVESTIGATION_VERSION: u32 = INVESTIGATION_SCHEMA_VERSION;
pub const MAX_INVESTIGATION_POLICY_BYTES: u64 = 512 * 1024;
pub const RECON_SEED_SCHEMA_VERSION: u32 = 1;
const MAX_RECON_SOURCE_BYTES: usize = 512;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InvestigationBudgets {
    pub max_planner_turns: u32,
    pub max_calls: u32,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    /// Stop after this many consecutive turns without a new observation or
    /// validated status transition. `None` preserves legacy session behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_consecutive_unproductive_turns: Option<u32>,
}

/// User-supplied links from selected M1 hypotheses to existing M4 queue items.
/// The source catalog confers no HTTP authority of its own.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReconSeedPolicy {
    pub bundle_sha256: String,
    pub links: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceEvidenceSeed {
    pub artifact_id: String,
    pub source: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceHypothesisSeed {
    pub hypothesis_id: String,
    pub statement: String,
    pub recon_status: smash_agent::protocol::HypothesisStatus,
    pub evidence: Vec<SourceEvidenceSeed>,
    pub queue_item_ids: Vec<String>,
}

/// Frozen source provenance embedded in the effective M4 policy. This is not
/// source content, an HTTP route catalog, or dynamic vulnerability evidence.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReconInvestigationSeed {
    pub schema_version: u32,
    pub source_run_id: String,
    pub bundle_sha256: String,
    pub hypotheses: Vec<SourceHypothesisSeed>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HttpInvestigationPolicy {
    pub schema_version: u32,
    pub campaign: HttpCampaignPolicy,
    /// Fixed work and read authority. Thoughts may update only status/evidence.
    pub queue: Vec<QueueItem>,
    pub budgets: InvestigationBudgets,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recon: Option<ReconSeedPolicy>,
    /// Generated only after the source bundle has passed full offline checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recon_seed: Option<ReconInvestigationSeed>,
}

impl HttpInvestigationPolicy {
    pub fn validate(&self) -> Result<(), HttpCampaignError> {
        self.campaign.validate()?;
        if self.schema_version != M4_INVESTIGATION_VERSION
            || self.campaign.effect.is_some()
            || self.campaign.calls.is_empty()
            || self.campaign.calls.len() > MAX_INVESTIGATION_CALLS
            || self.campaign.calls.iter().any(|case| {
                self.campaign
                    .target
                    .route(&case.call.route_id)
                    .map(|route| route.effect)
                    != Some(OperationEffect::ReadOnly)
            })
            || self.queue.is_empty()
            || self.queue.len() > MAX_INVESTIGATION_ITEMS
            || self
                .queue
                .iter()
                .any(|item| item.status != QueueStatus::Pending || !item.evidence_turns.is_empty())
            || self.budgets.max_calls == 0
            || self.budgets.max_calls as usize > MAX_INVESTIGATION_ITEMS
            || self.budgets.max_calls > self.campaign.target.limits.max_calls
            || self.budgets.max_planner_turns <= self.budgets.max_calls
            || self.budgets.max_planner_turns > MAX_INVESTIGATION_ITEMS as u32 + 1
            || self.budgets.max_input_tokens == 0
            || self.budgets.max_output_tokens == 0
            || self
                .budgets
                .max_consecutive_unproductive_turns
                .is_some_and(|limit| limit == 0 || limit > MAX_INVESTIGATION_ITEMS as u32)
        {
            return Err(HttpCampaignError(
                "M4 admits nonempty read-only catalogs, pending bounded work, and budgets with a final planning turn"
                    .into(),
            ));
        }
        self.validate_recon_seed()?;
        let calls = self.call_descriptors();
        let hypotheses = self.initial_hypotheses();
        let context = InvestigationContext {
            run_id: &self.campaign.run_id,
            next_turn: 1,
            calls: &calls,
            observations: &[],
            hypotheses: &hypotheses,
            queue: &self.queue,
            remaining_usage: self.usage_limit(),
        };
        validate_investigation_context(&context).map_err(|error| HttpCampaignError(error.0))
    }

    /// Attach one verified M1 bundle after checking its digest and all selected
    /// hypothesis/evidence links. The repository is never reopened.
    pub fn attach_verified_recon(
        &mut self,
        verified: &VerifiedReconBundle,
    ) -> Result<(), HttpCampaignError> {
        let selection = self.recon.as_ref().ok_or_else(|| {
            HttpCampaignError("--recon-bundle requires a recon selection in the M4 policy".into())
        })?;
        if self.recon_seed.is_some() {
            return Err(HttpCampaignError(
                "recon_seed is generated from a verified bundle, not accepted as CLI input".into(),
            ));
        }
        if selection.bundle_sha256 != verified.bundle_sha256 {
            return Err(HttpCampaignError(
                "verified recon bundle digest differs from the M4 selection".into(),
            ));
        }
        self.recon_seed = Some(project_recon_seed(verified, selection)?);
        Ok(())
    }

    pub fn initial_hypotheses(&self) -> Vec<Hypothesis> {
        self.recon_seed
            .iter()
            .flat_map(|seed| &seed.hypotheses)
            .map(|source| Hypothesis {
                hypothesis_id: source.hypothesis_id.clone(),
                statement: source.statement.clone(),
                // M1 support is source-observed, never M4 runtime evidence.
                status: HypothesisStatus::Open,
                evidence_turns: Vec::new(),
            })
            .collect()
    }

    pub fn call_descriptors(&self) -> Vec<CallDescriptor> {
        self.campaign
            .calls
            .iter()
            .enumerate()
            .map(|(index, case)| CallDescriptor {
                index,
                route_id: case.call.route_id.clone(),
                arguments: case.call.arguments.clone(),
            })
            .collect()
    }

    pub fn usage_limit(&self) -> Usage {
        Usage {
            input_tokens: self.budgets.max_input_tokens,
            output_tokens: self.budgets.max_output_tokens,
        }
    }

    pub fn sha256(&self) -> Result<String, HttpCampaignError> {
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(self)?)))
    }

    fn validate_recon_seed(&self) -> Result<(), HttpCampaignError> {
        let (selection, seed) = match (&self.recon, &self.recon_seed) {
            (None, None) => return Ok(()),
            (Some(selection), Some(seed)) => (selection, seed),
            _ => {
                return Err(HttpCampaignError(
                    "recon selection and frozen recon seed must either both be present or both absent"
                        .into(),
                ));
            }
        };
        if seed.schema_version != RECON_SEED_SCHEMA_VERSION
            || !valid_digest(&selection.bundle_sha256)
            || seed.bundle_sha256 != selection.bundle_sha256
            || !valid_id(&seed.source_run_id)
            || seed.hypotheses.len() != selection.links.len()
            || seed.hypotheses.is_empty()
            || seed.hypotheses.len() > MAX_INVESTIGATION_ITEMS
        {
            return Err(HttpCampaignError(
                "invalid frozen recon seed identity or cardinality".into(),
            ));
        }
        let queue_ids: BTreeSet<&str> = self
            .queue
            .iter()
            .map(|item| item.item_id.as_str())
            .collect();
        let mut evidence_count = 0usize;
        let mut link_count = 0usize;
        for source in &seed.hypotheses {
            if !valid_id(&source.hypothesis_id)
                || !valid_text(&source.statement, 1024)
                || selection.links.get(&source.hypothesis_id) != Some(&source.queue_item_ids)
                || source.queue_item_ids.is_empty()
                || source
                    .queue_item_ids
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                || source
                    .queue_item_ids
                    .iter()
                    .any(|item_id| !queue_ids.contains(item_id.as_str()))
                || source.evidence.is_empty()
            {
                return Err(HttpCampaignError(
                    "recon hypothesis, evidence, or queue linkage is invalid".into(),
                ));
            }
            for evidence in &source.evidence {
                if !valid_id(&evidence.artifact_id)
                    || !valid_text(&evidence.source, MAX_RECON_SOURCE_BYTES)
                    || !valid_digest(&evidence.sha256)
                    || evidence.bytes == 0
                {
                    return Err(HttpCampaignError(
                        "recon evidence metadata is invalid".into(),
                    ));
                }
            }
            evidence_count = evidence_count.saturating_add(source.evidence.len());
            link_count = link_count.saturating_add(source.queue_item_ids.len());
        }
        let mut hypothesis_ids = BTreeSet::new();
        if seed
            .hypotheses
            .iter()
            .any(|source| !hypothesis_ids.insert(source.hypothesis_id.as_str()))
            || evidence_count.saturating_add(seed.hypotheses.len()) > MAX_INVESTIGATION_ITEMS
            || link_count > MAX_INVESTIGATION_ITEMS
        {
            return Err(HttpCampaignError(
                "recon seed exceeds the M4 hypothesis/evidence/link bounds".into(),
            ));
        }
        Ok(())
    }
}

fn project_recon_seed(
    verified: &VerifiedReconBundle,
    selection: &ReconSeedPolicy,
) -> Result<ReconInvestigationSeed, HttpCampaignError> {
    if selection.links.is_empty() || selection.links.len() > MAX_INVESTIGATION_ITEMS {
        return Err(HttpCampaignError(
            "recon selection requires 1..=32 source hypotheses".into(),
        ));
    }
    let mut hypotheses = Vec::with_capacity(selection.links.len());
    for (hypothesis_id, queue_item_ids) in &selection.links {
        let hypothesis = verified
            .bundle
            .hypotheses
            .iter()
            .find(|hypothesis| &hypothesis.hypothesis_id == hypothesis_id)
            .ok_or_else(|| {
                HttpCampaignError("recon selection references an unknown source hypothesis".into())
            })?;
        if hypothesis.evidence_ids.is_empty() {
            return Err(HttpCampaignError(
                "selected recon hypothesis has no source evidence".into(),
            ));
        }
        let mut evidence = Vec::with_capacity(hypothesis.evidence_ids.len());
        for artifact_id in &hypothesis.evidence_ids {
            let artifact = verified
                .bundle
                .artifacts
                .iter()
                .find(|artifact| &artifact.artifact_id == artifact_id)
                .ok_or_else(|| {
                    HttpCampaignError("recon hypothesis references unknown source evidence".into())
                })?;
            evidence.push(SourceEvidenceSeed {
                artifact_id: artifact.artifact_id.clone(),
                source: artifact.source.clone(),
                sha256: artifact.sha256.clone(),
                bytes: artifact.bytes,
            });
        }
        hypotheses.push(SourceHypothesisSeed {
            hypothesis_id: hypothesis.hypothesis_id.clone(),
            statement: hypothesis.statement.clone(),
            recon_status: hypothesis.status,
            evidence,
            queue_item_ids: queue_item_ids.clone(),
        });
    }
    Ok(ReconInvestigationSeed {
        schema_version: RECON_SEED_SCHEMA_VERSION,
        source_run_id: verified.bundle.run_id.clone(),
        bundle_sha256: verified.bundle_sha256.clone(),
        hypotheses,
    })
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_progress_budget_is_additive_and_omitted_when_unconfigured() {
        let legacy = serde_json::json!({
            "max_planner_turns": 3,
            "max_calls": 2,
            "max_input_tokens": 16,
            "max_output_tokens": 16
        });
        let budgets: InvestigationBudgets = serde_json::from_value(legacy.clone()).unwrap();
        assert_eq!(budgets.max_consecutive_unproductive_turns, None);
        assert_eq!(serde_json::to_value(&budgets).unwrap(), legacy);

        let configured = serde_json::json!({
            "max_planner_turns": 3,
            "max_calls": 2,
            "max_input_tokens": 16,
            "max_output_tokens": 16,
            "max_consecutive_unproductive_turns": 2
        });
        let budgets: InvestigationBudgets = serde_json::from_value(configured.clone()).unwrap();
        assert_eq!(budgets.max_consecutive_unproductive_turns, Some(2));
        assert_eq!(serde_json::to_value(&budgets).unwrap(), configured);
    }
}
