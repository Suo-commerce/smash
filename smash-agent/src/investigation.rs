//! Strict, bounded M4 investigation decisions.
//!
//! This protocol is deliberately independent of the M1 planner. Investigation
//! thoughts carry concise summaries and auditable state, never hidden reasoning.

use crate::protocol::PlannerError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const INVESTIGATION_SCHEMA_VERSION: u32 = 1;
pub const MAX_INVESTIGATION_RESPONSE_BYTES: usize = 64 * 1024;
pub const MAX_INVESTIGATION_ITEMS: usize = 32;
pub const MAX_INVESTIGATION_CALLS: usize = 64;

const MAX_ID_BYTES: usize = 96;
const MAX_STATEMENT_BYTES: usize = 1024;
const MAX_SUMMARY_BYTES: usize = 2048;
const MAX_ARGUMENTS_PER_CALL: usize = 16;
const MAX_ARGUMENT_BYTES_PER_CALL: usize = 4096;
const MAX_ARGUMENT_VALUE_BYTES: usize = 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CallDescriptor {
    pub index: usize,
    pub route_id: String,
    pub arguments: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservationDescriptor {
    pub sequence: u32,
    pub item_id: String,
    pub call_index: usize,
    pub observed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Hypothesis {
    pub hypothesis_id: String,
    pub statement: String,
    pub status: HypothesisStatus,
    pub evidence_turns: Vec<u32>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisStatus {
    Open,
    Inconclusive,
    Supported,
    Refuted,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QueueItem {
    pub item_id: String,
    pub purpose: String,
    pub allowed_calls: Vec<usize>,
    pub status: QueueStatus,
    pub evidence_turns: Vec<u32>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueueStatus {
    Pending,
    Active,
    Complete,
    Blocked,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Thought {
    pub summary: String,
    pub hypotheses: Vec<Hypothesis>,
    pub queue: Vec<QueueItem>,
    pub usage: Usage,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum InvestigationAction {
    Investigate { item_id: String, call_index: usize },
    Complete,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InvestigationOutput {
    pub action: InvestigationAction,
    pub thought: Thought,
    /// Exact bounded bytes consumed for this decision, retained for checkpointing.
    pub response_bytes: Vec<u8>,
    pub response_sha256: String,
}

#[derive(Clone, Debug)]
pub struct InvestigationContext<'a> {
    pub run_id: &'a str,
    pub next_turn: u32,
    pub calls: &'a [CallDescriptor],
    pub observations: &'a [ObservationDescriptor],
    pub hypotheses: &'a [Hypothesis],
    pub queue: &'a [QueueItem],
    pub remaining_usage: Usage,
}

pub trait InvestigationPlanner {
    fn next_decision(
        &mut self,
        context: &InvestigationContext<'_>,
    ) -> Result<InvestigationOutput, PlannerError>;

    fn restore(&mut self, consumed: &[Vec<u8>]) -> Result<(), PlannerError> {
        if consumed.is_empty() {
            Ok(())
        } else {
            Err(PlannerError(
                "restoring consumed responses is unsupported".to_owned(),
            ))
        }
    }
}

/// A finite response script with deterministic, exact-prefix restoration.
#[derive(Clone, Debug)]
pub struct ScriptedInvestigationPlanner {
    initial_responses: Vec<Vec<u8>>,
    responses: VecDeque<Vec<u8>>,
    pub decisions: usize,
}

impl ScriptedInvestigationPlanner {
    pub fn new(responses: impl IntoIterator<Item = impl Into<Vec<u8>>>) -> Self {
        let responses: VecDeque<Vec<u8>> = responses.into_iter().map(Into::into).collect();
        Self {
            initial_responses: responses.iter().cloned().collect(),
            responses,
            decisions: 0,
        }
    }

    pub fn from_json(responses: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::new(
            responses
                .into_iter()
                .map(|response| response.into().into_bytes()),
        )
    }

    pub fn remaining(&self) -> usize {
        self.responses.len()
    }

    pub fn validate_script(&self) -> Result<(), PlannerError> {
        if self
            .responses
            .iter()
            .any(|response| response.len() > MAX_INVESTIGATION_RESPONSE_BYTES)
        {
            return Err(PlannerError(
                "investigation script contains an oversized response".to_owned(),
            ));
        }
        Ok(())
    }
}

impl InvestigationPlanner for ScriptedInvestigationPlanner {
    fn next_decision(
        &mut self,
        context: &InvestigationContext<'_>,
    ) -> Result<InvestigationOutput, PlannerError> {
        let bytes = self
            .responses
            .pop_front()
            .ok_or_else(|| PlannerError("scripted investigation planner exhausted".to_owned()))?;
        // Every response is consumed and hashed once, including invalid responses.
        let digest = Sha256::digest(&bytes);
        let response_sha256 = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        let (action, thought) = decode_investigation_response(&bytes, context)?;
        self.decisions += 1;
        Ok(InvestigationOutput {
            action,
            thought,
            response_bytes: bytes,
            response_sha256,
        })
    }

    fn restore(&mut self, consumed: &[Vec<u8>]) -> Result<(), PlannerError> {
        if consumed.len() > self.initial_responses.len()
            || !consumed
                .iter()
                .zip(&self.initial_responses)
                .all(|(actual, expected)| actual == expected)
        {
            return Err(PlannerError(
                "consumed responses are not the exact initial script prefix".to_owned(),
            ));
        }
        self.responses = self.initial_responses[consumed.len()..]
            .iter()
            .cloned()
            .collect();
        self.decisions = consumed.len();
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum WireResponse {
    Investigate {
        schema_version: u32,
        item_id: String,
        call_index: usize,
        thought: Thought,
    },
    Complete {
        schema_version: u32,
        thought: Thought,
    },
}

/// Decode and validate exactly one complete investigation response.
pub fn decode_investigation_response(
    bytes: &[u8],
    context: &InvestigationContext<'_>,
) -> Result<(InvestigationAction, Thought), PlannerError> {
    if bytes.len() > MAX_INVESTIGATION_RESPONSE_BYTES {
        return Err(PlannerError(format!(
            "investigation response exceeds {MAX_INVESTIGATION_RESPONSE_BYTES} bytes"
        )));
    }
    std::str::from_utf8(bytes)
        .map_err(|error| PlannerError(format!("investigation response is not UTF-8: {error}")))?;
    validate_context(context)?;

    let response: WireResponse = serde_json::from_slice(bytes)
        .map_err(|error| PlannerError(format!("invalid investigation JSON: {error}")))?;
    let (schema_version, action, thought) = match response {
        WireResponse::Investigate {
            schema_version,
            item_id,
            call_index,
            thought,
        } => (
            schema_version,
            InvestigationAction::Investigate {
                item_id,
                call_index,
            },
            thought,
        ),
        WireResponse::Complete {
            schema_version,
            thought,
        } => (schema_version, InvestigationAction::Complete, thought),
    };
    if schema_version != INVESTIGATION_SCHEMA_VERSION {
        return Err(PlannerError("unsupported investigation schema".to_owned()));
    }

    let known_evidence = known_evidence(context.observations);
    validate_thought(&thought, context, &known_evidence)?;
    validate_action(&action, &thought, context)?;
    Ok((action, thought))
}

pub fn validate_investigation_context(
    context: &InvestigationContext<'_>,
) -> Result<(), PlannerError> {
    validate_context(context)
}

fn validate_context(context: &InvestigationContext<'_>) -> Result<(), PlannerError> {
    validate_id("run_id", context.run_id)?;
    if context.calls.len() > MAX_INVESTIGATION_CALLS
        || context.observations.len() > MAX_INVESTIGATION_ITEMS
        || context.hypotheses.len() > MAX_INVESTIGATION_ITEMS
        || context.next_turn == 0
        || context.next_turn as usize != context.observations.len() + 1
    {
        return Err(PlannerError(
            "invalid investigation context bounds".to_owned(),
        ));
    }

    for (expected_index, call) in context.calls.iter().enumerate() {
        if call.index != expected_index {
            return Err(PlannerError(
                "investigation call indices must be exactly 0..n".to_owned(),
            ));
        }
        validate_id("route_id", &call.route_id)?;
        if call.arguments.len() > MAX_ARGUMENTS_PER_CALL {
            return Err(PlannerError(
                "too many investigation call arguments".to_owned(),
            ));
        }
        let mut argument_bytes = 0usize;
        for (name, value) in &call.arguments {
            validate_id("argument name", name)?;
            if value.len() > MAX_ARGUMENT_VALUE_BYTES || value.chars().any(char::is_control) {
                return Err(PlannerError(
                    "invalid investigation argument value".to_owned(),
                ));
            }
            argument_bytes = argument_bytes
                .checked_add(name.len().saturating_add(value.len()))
                .ok_or_else(|| PlannerError("investigation arguments are too large".to_owned()))?;
        }
        if argument_bytes > MAX_ARGUMENT_BYTES_PER_CALL {
            return Err(PlannerError(
                "investigation arguments are too large".to_owned(),
            ));
        }
    }

    for (index, observation) in context.observations.iter().enumerate() {
        if observation.sequence as usize != index + 1 {
            return Err(PlannerError(
                "investigation observations are not a contiguous history".to_owned(),
            ));
        }
        validate_id("observation item_id", &observation.item_id)?;
        let item = context
            .queue
            .iter()
            .find(|item| item.item_id == observation.item_id)
            .ok_or_else(|| {
                PlannerError("observation references an unknown queue item".to_owned())
            })?;
        if observation.call_index >= context.calls.len()
            || !item.allowed_calls.contains(&observation.call_index)
        {
            return Err(PlannerError(
                "observation contains an unadmitted item/call pair".to_owned(),
            ));
        }
    }

    let known_evidence = known_evidence(context.observations);
    validate_queue(context.queue, context.calls.len(), &known_evidence)?;
    validate_hypotheses(context.hypotheses, &known_evidence)?;
    Ok(())
}

fn known_evidence(observations: &[ObservationDescriptor]) -> BTreeMap<u32, &ObservationDescriptor> {
    observations
        .iter()
        .filter(|observation| observation.observed)
        .map(|observation| (observation.sequence, observation))
        .collect()
}

fn validate_thought(
    thought: &Thought,
    context: &InvestigationContext<'_>,
    known_evidence: &BTreeMap<u32, &ObservationDescriptor>,
) -> Result<(), PlannerError> {
    validate_text("thought summary", &thought.summary, MAX_SUMMARY_BYTES)?;
    if thought.usage.input_tokens > context.remaining_usage.input_tokens
        || thought.usage.output_tokens > context.remaining_usage.output_tokens
    {
        return Err(PlannerError(
            "investigation thought exceeds remaining usage".to_owned(),
        ));
    }

    validate_hypotheses(&thought.hypotheses, known_evidence)?;
    if thought.hypotheses.len() < context.hypotheses.len() {
        return Err(PlannerError("prior hypotheses were dropped".to_owned()));
    }
    for (prior, new) in context.hypotheses.iter().zip(&thought.hypotheses) {
        if prior.hypothesis_id != new.hypothesis_id || prior.statement != new.statement {
            return Err(PlannerError(
                "prior hypotheses are not an immutable prefix".to_owned(),
            ));
        }
        if !new.evidence_turns.starts_with(&prior.evidence_turns) {
            return Err(PlannerError(
                "prior hypothesis evidence was dropped".to_owned(),
            ));
        }
        if !valid_hypothesis_transition(prior.status, new.status) {
            return Err(PlannerError(
                "invalid hypothesis status transition".to_owned(),
            ));
        }
    }

    validate_queue(&thought.queue, context.calls.len(), known_evidence)?;
    if thought.queue.len() != context.queue.len() {
        return Err(PlannerError(
            "investigation queue policy changed".to_owned(),
        ));
    }
    for (prior, new) in context.queue.iter().zip(&thought.queue) {
        if prior.item_id != new.item_id
            || prior.purpose != new.purpose
            || prior.allowed_calls != new.allowed_calls
        {
            return Err(PlannerError(
                "investigation queue identity or policy changed".to_owned(),
            ));
        }
        if !valid_queue_transition(prior.status, new.status) {
            return Err(PlannerError("invalid queue status transition".to_owned()));
        }
        if !new.evidence_turns.starts_with(&prior.evidence_turns) {
            return Err(PlannerError("prior queue evidence was dropped".to_owned()));
        }
        if new.status == QueueStatus::Complete
            && !matches!(prior.status, QueueStatus::Active | QueueStatus::Complete)
        {
            return Err(PlannerError(
                "a queue item can complete only from active".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_hypotheses(
    hypotheses: &[Hypothesis],
    known_evidence: &BTreeMap<u32, &ObservationDescriptor>,
) -> Result<(), PlannerError> {
    if hypotheses.len() > MAX_INVESTIGATION_ITEMS {
        return Err(PlannerError("too many investigation hypotheses".to_owned()));
    }
    let mut ids = BTreeSet::new();
    for hypothesis in hypotheses {
        validate_id("hypothesis_id", &hypothesis.hypothesis_id)?;
        validate_text(
            "hypothesis statement",
            &hypothesis.statement,
            MAX_STATEMENT_BYTES,
        )?;
        if !ids.insert(hypothesis.hypothesis_id.as_str()) {
            return Err(PlannerError(
                "duplicate investigation hypothesis".to_owned(),
            ));
        }
        validate_evidence(&hypothesis.evidence_turns, known_evidence)?;
        if matches!(
            hypothesis.status,
            HypothesisStatus::Supported | HypothesisStatus::Refuted
        ) && hypothesis.evidence_turns.is_empty()
        {
            return Err(PlannerError(
                "supported or refuted hypotheses require evidence".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_queue(
    queue: &[QueueItem],
    calls_len: usize,
    known_evidence: &BTreeMap<u32, &ObservationDescriptor>,
) -> Result<(), PlannerError> {
    if queue.is_empty() || queue.len() > MAX_INVESTIGATION_ITEMS {
        return Err(PlannerError(
            "investigation queue must contain 1..=32 items".to_owned(),
        ));
    }
    let mut ids = BTreeSet::new();
    let mut active_items = 0usize;
    for item in queue {
        validate_id("item_id", &item.item_id)?;
        validate_text("queue purpose", &item.purpose, MAX_STATEMENT_BYTES)?;
        if !ids.insert(item.item_id.as_str()) {
            return Err(PlannerError(
                "duplicate investigation queue item".to_owned(),
            ));
        }
        if item.allowed_calls.is_empty()
            || item.allowed_calls.windows(2).any(|pair| pair[0] >= pair[1])
            || item
                .allowed_calls
                .iter()
                .any(|call_index| *call_index >= calls_len)
        {
            return Err(PlannerError(
                "queue allowed_calls must be nonempty, sorted, unique, and known".to_owned(),
            ));
        }
        validate_evidence(&item.evidence_turns, known_evidence)?;
        if item.status == QueueStatus::Active {
            active_items += 1;
        }
        if item.status == QueueStatus::Complete
            && !item.evidence_turns.iter().any(|turn| {
                known_evidence
                    .get(turn)
                    .is_some_and(|observation| observation.item_id == item.item_id)
            })
        {
            return Err(PlannerError(
                "a complete queue item requires same-item evidence".to_owned(),
            ));
        }
    }
    if active_items > 1 {
        return Err(PlannerError(
            "an investigation queue may have at most one active item".to_owned(),
        ));
    }
    Ok(())
}

fn validate_evidence(
    evidence_turns: &[u32],
    known_evidence: &BTreeMap<u32, &ObservationDescriptor>,
) -> Result<(), PlannerError> {
    if evidence_turns.windows(2).any(|pair| pair[0] >= pair[1])
        || evidence_turns
            .iter()
            .any(|turn| !known_evidence.contains_key(turn))
    {
        return Err(PlannerError(
            "evidence turns must be sorted, unique, and known observations".to_owned(),
        ));
    }
    Ok(())
}

fn validate_action(
    action: &InvestigationAction,
    thought: &Thought,
    context: &InvestigationContext<'_>,
) -> Result<(), PlannerError> {
    match action {
        InvestigationAction::Investigate {
            item_id,
            call_index,
        } => {
            let item = thought
                .queue
                .iter()
                .find(|item| item.item_id == *item_id)
                .ok_or_else(|| {
                    PlannerError("investigation action selects an unknown item".to_owned())
                })?;
            let prior = context
                .queue
                .iter()
                .find(|prior| prior.item_id == *item_id)
                .ok_or_else(|| {
                    PlannerError("investigation action selects an unknown item".to_owned())
                })?;
            if item.status != QueueStatus::Active
                || !matches!(prior.status, QueueStatus::Pending | QueueStatus::Active)
            {
                return Err(PlannerError(
                    "investigation action must select an active pending/active item".to_owned(),
                ));
            }
            if *call_index >= context.calls.len() || !item.allowed_calls.contains(call_index) {
                return Err(PlannerError(
                    "investigation action selects an unadmitted call".to_owned(),
                ));
            }
        }
        InvestigationAction::Complete => {
            if !thought
                .queue
                .iter()
                .all(|item| matches!(item.status, QueueStatus::Complete | QueueStatus::Blocked))
            {
                return Err(PlannerError(
                    "completion requires every queue item to be complete or blocked".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn valid_hypothesis_transition(prior: HypothesisStatus, new: HypothesisStatus) -> bool {
    match prior {
        HypothesisStatus::Open => true,
        HypothesisStatus::Inconclusive => new != HypothesisStatus::Open,
        HypothesisStatus::Supported => new == HypothesisStatus::Supported,
        HypothesisStatus::Refuted => new == HypothesisStatus::Refuted,
    }
}

fn valid_queue_transition(prior: QueueStatus, new: QueueStatus) -> bool {
    match prior {
        QueueStatus::Pending => matches!(
            new,
            QueueStatus::Pending | QueueStatus::Active | QueueStatus::Blocked
        ),
        QueueStatus::Active => matches!(
            new,
            QueueStatus::Active | QueueStatus::Complete | QueueStatus::Blocked
        ),
        QueueStatus::Complete => new == QueueStatus::Complete,
        QueueStatus::Blocked => new == QueueStatus::Blocked,
    }
}

fn validate_id(field: &str, id: &str) -> Result<(), PlannerError> {
    if id.is_empty()
        || id.len() > MAX_ID_BYTES
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(PlannerError(format!("invalid {field}")));
    }
    Ok(())
}

fn validate_text(field: &str, text: &str, max_bytes: usize) -> Result<(), PlannerError> {
    if text.is_empty() || text.len() > max_bytes || text.chars().any(char::is_control) {
        return Err(PlannerError(format!("invalid {field}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(index: usize) -> CallDescriptor {
        CallDescriptor {
            index,
            route_id: format!("route-{index}"),
            arguments: BTreeMap::new(),
        }
    }

    fn item(item_id: &str, status: QueueStatus) -> QueueItem {
        QueueItem {
            item_id: item_id.to_owned(),
            purpose: "Inspect the bounded route".to_owned(),
            allowed_calls: vec![0],
            status,
            evidence_turns: vec![],
        }
    }

    fn thought(status: QueueStatus) -> Thought {
        Thought {
            summary: "Bounded investigation summary".to_owned(),
            hypotheses: vec![],
            queue: vec![item("item-1", status)],
            usage: Usage {
                input_tokens: 1,
                output_tokens: 1,
            },
        }
    }

    fn make_context<'a>(
        observations: &'a [ObservationDescriptor],
        hypotheses: &'a [Hypothesis],
        queue: &'a [QueueItem],
        calls: &'a [CallDescriptor],
    ) -> InvestigationContext<'a> {
        InvestigationContext {
            run_id: "run-1",
            next_turn: observations.len() as u32 + 1,
            calls,
            observations,
            hypotheses,
            queue,
            remaining_usage: Usage {
                input_tokens: 100,
                output_tokens: 100,
            },
        }
    }

    fn response(action: InvestigationAction, thought: &Thought) -> Vec<u8> {
        let mut value = serde_json::to_value(action).unwrap();
        let object = value.as_object_mut().unwrap();
        object.insert(
            "schema_version".to_owned(),
            serde_json::Value::from(INVESTIGATION_SCHEMA_VERSION),
        );
        object.insert("thought".to_owned(), serde_json::to_value(thought).unwrap());
        serde_json::to_vec(&value).unwrap()
    }

    fn investigate_response(thought: &Thought) -> Vec<u8> {
        response(
            InvestigationAction::Investigate {
                item_id: "item-1".to_owned(),
                call_index: 0,
            },
            thought,
        )
    }

    fn observation(sequence: u32, observed: bool) -> ObservationDescriptor {
        ObservationDescriptor {
            sequence,
            item_id: "item-1".to_owned(),
            call_index: 0,
            observed,
        }
    }

    fn hypothesis(id: &str, status: HypothesisStatus, evidence_turns: Vec<u32>) -> Hypothesis {
        Hypothesis {
            hypothesis_id: id.to_owned(),
            statement: "The route is bounded".to_owned(),
            status,
            evidence_turns,
        }
    }

    #[test]
    fn strict_fields_and_unknown_authority_fields_are_rejected() {
        let calls = [call(0)];
        let queue = [item("item-1", QueueStatus::Pending)];
        let context = make_context(&[], &[], &queue, &calls);
        let bytes = investigate_response(&thought(QueueStatus::Active));
        assert!(decode_investigation_response(&bytes, &context).is_ok());

        for field in ["run_id", "next_turn", "calls", "remaining_usage"] {
            let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), serde_json::json!("forged"));
            assert!(
                decode_investigation_response(&serde_json::to_vec(&value).unwrap(), &context)
                    .is_err()
            );
        }

        let mut without_thought: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        without_thought.as_object_mut().unwrap().remove("thought");
        assert!(decode_investigation_response(
            &serde_json::to_vec(&without_thought).unwrap(),
            &context
        )
        .is_err());

        let mut complete_with_authority: serde_json::Value = serde_json::from_slice(&response(
            InvestigationAction::Complete,
            &thought(QueueStatus::Blocked),
        ))
        .unwrap();
        complete_with_authority
            .as_object_mut()
            .unwrap()
            .insert("call_index".to_owned(), serde_json::json!(0));
        assert!(decode_investigation_response(
            &serde_json::to_vec(&complete_with_authority).unwrap(),
            &context
        )
        .is_err());

        assert!(decode_investigation_response(&[0xff], &context).is_err());
        let mut trailing = bytes.clone();
        trailing.extend_from_slice(b" {}");
        assert!(decode_investigation_response(&trailing, &context).is_err());
        let unsupported = investigate_response(&thought(QueueStatus::Active));
        let mut unsupported: serde_json::Value = serde_json::from_slice(&unsupported).unwrap();
        unsupported
            .as_object_mut()
            .unwrap()
            .insert("schema_version".to_owned(), serde_json::json!(2));
        assert!(decode_investigation_response(
            &serde_json::to_vec(&unsupported).unwrap(),
            &context
        )
        .is_err());
    }

    #[test]
    fn digest_is_sha256_of_the_exact_raw_response() {
        let calls = [call(0)];
        let queue = [item("item-1", QueueStatus::Pending)];
        let context = make_context(&[], &[], &queue, &calls);
        let bytes = investigate_response(&thought(QueueStatus::Active));
        let expected = format!("{:x}", Sha256::digest(&bytes));
        let mut planner = ScriptedInvestigationPlanner::new([bytes.clone()]);
        let output = planner.next_decision(&context).unwrap();
        assert_eq!(output.response_sha256, expected);
        assert_eq!(output.response_sha256.len(), 64);
        assert_eq!(output.response_bytes, bytes);
    }

    #[test]
    fn one_response_is_consumed_without_retry_and_exhaustion_fails_closed() {
        let calls = [call(0)];
        let queue = [item("item-1", QueueStatus::Pending)];
        let context = make_context(&[], &[], &queue, &calls);
        let valid = investigate_response(&thought(QueueStatus::Active));
        let mut planner = ScriptedInvestigationPlanner::new([b"not JSON".to_vec(), valid]);
        assert!(planner.next_decision(&context).is_err());
        assert_eq!(planner.decisions, 0);
        assert_eq!(planner.remaining(), 1);
        assert!(planner.next_decision(&context).is_ok());
        assert_eq!(planner.decisions, 1);
        assert_eq!(planner.remaining(), 0);
        assert!(planner.next_decision(&context).is_err());
        assert_eq!(planner.decisions, 1);
    }

    #[test]
    fn restore_accepts_only_the_exact_initial_script_prefix() {
        let mut planner = ScriptedInvestigationPlanner::from_json(["one", "two", "three"]);
        planner.restore(&[b"one".to_vec()]).unwrap();
        assert_eq!(planner.remaining(), 2);
        assert_eq!(planner.decisions, 1);
        assert!(planner.restore(&[b"modified".to_vec()]).is_err());
        assert!(planner
            .restore(&[b"one".to_vec(), b"three".to_vec()])
            .is_err());
        assert_eq!(planner.remaining(), 2);
        planner.restore(&[]).unwrap();
        assert_eq!(planner.remaining(), 3);
        assert_eq!(planner.decisions, 0);

        struct NoRestore;
        impl InvestigationPlanner for NoRestore {
            fn next_decision(
                &mut self,
                _: &InvestigationContext<'_>,
            ) -> Result<InvestigationOutput, PlannerError> {
                unreachable!()
            }
        }
        let mut no_restore = NoRestore;
        assert!(no_restore.restore(&[]).is_ok());
        assert!(no_restore.restore(&[b"one".to_vec()]).is_err());
    }

    #[test]
    fn selection_requires_an_admitted_catalog_pair() {
        let calls = [call(0), call(1)];
        let mut queue_item = item("item-1", QueueStatus::Pending);
        queue_item.allowed_calls = vec![1];
        let queue = [queue_item.clone()];
        let context = make_context(&[], &[], &queue, &calls);
        let mut selected = thought(QueueStatus::Active);
        selected.queue = vec![queue_item];
        selected.queue[0].status = QueueStatus::Active;
        let admitted = response(
            InvestigationAction::Investigate {
                item_id: "item-1".to_owned(),
                call_index: 1,
            },
            &selected,
        );
        let decoded = decode_investigation_response(&admitted, &context);
        assert!(decoded.is_ok(), "{decoded:?}");
        let unadmitted = response(
            InvestigationAction::Investigate {
                item_id: "item-1".to_owned(),
                call_index: 0,
            },
            &selected,
        );
        assert!(decode_investigation_response(&unadmitted, &context).is_err());
    }

    #[test]
    fn arbitrary_unknown_action_index_fails() {
        let calls = [call(0)];
        let queue = [item("item-1", QueueStatus::Pending)];
        let context = make_context(&[], &[], &queue, &calls);
        let bytes = response(
            InvestigationAction::Investigate {
                item_id: "item-1".to_owned(),
                call_index: 99,
            },
            &thought(QueueStatus::Active),
        );
        assert!(decode_investigation_response(&bytes, &context).is_err());
    }

    #[test]
    fn supported_evidence_must_be_known_and_observed() {
        let calls = [call(0)];
        let observations = [observation(1, true), observation(2, false)];
        let prior = [hypothesis("h1", HypothesisStatus::Open, vec![])];
        let queue = [item("item-1", QueueStatus::Pending)];
        let context = make_context(&observations, &prior, &queue, &calls);
        for evidence in [vec![2], vec![99]] {
            let mut selected = thought(QueueStatus::Active);
            selected.hypotheses = vec![hypothesis("h1", HypothesisStatus::Supported, evidence)];
            assert!(
                decode_investigation_response(&investigate_response(&selected), &context).is_err()
            );
        }
        let mut supported = thought(QueueStatus::Active);
        supported.hypotheses = vec![hypothesis("h1", HypothesisStatus::Supported, vec![1])];
        assert!(decode_investigation_response(&investigate_response(&supported), &context).is_ok());

        let no_evidence = hypothesis("h1", HypothesisStatus::Supported, vec![]);
        let bad_prior = [no_evidence];
        assert!(decode_investigation_response(
            &investigate_response(&supported),
            &make_context(&observations, &bad_prior, &queue, &calls)
        )
        .is_err());
    }

    #[test]
    fn hypotheses_cannot_be_dropped_renamed_or_regressed() {
        let calls = [call(0)];
        let prior = [
            hypothesis("h1", HypothesisStatus::Open, vec![]),
            hypothesis("h2", HypothesisStatus::Open, vec![]),
        ];
        let queue = [item("item-1", QueueStatus::Pending)];
        let context = make_context(&[], &prior, &queue, &calls);

        let mut dropped = thought(QueueStatus::Active);
        dropped.hypotheses = prior[..1].to_vec();
        assert!(decode_investigation_response(&investigate_response(&dropped), &context).is_err());

        let mut renamed = thought(QueueStatus::Active);
        renamed.hypotheses = prior.to_vec();
        renamed.hypotheses[1].hypothesis_id = "renamed".to_owned();
        assert!(decode_investigation_response(&investigate_response(&renamed), &context).is_err());

        let supported_prior = [hypothesis("h1", HypothesisStatus::Supported, vec![1])];
        let observations = [observation(1, true)];
        let supported_context = make_context(&observations, &supported_prior, &queue, &calls);
        let mut regressed = thought(QueueStatus::Active);
        regressed.hypotheses = vec![hypothesis("h1", HypothesisStatus::Open, vec![1])];
        assert!(decode_investigation_response(
            &investigate_response(&regressed),
            &supported_context
        )
        .is_err());
    }

    #[test]
    fn queue_transitions_and_completion_are_enforced() {
        let calls = [call(0)];
        for (prior_status, new_status) in [
            (QueueStatus::Pending, QueueStatus::Complete),
            (QueueStatus::Active, QueueStatus::Pending),
            (QueueStatus::Complete, QueueStatus::Active),
            (QueueStatus::Blocked, QueueStatus::Pending),
        ] {
            let prior = [item("item-1", prior_status)];
            let context = make_context(&[], &[], &prior, &calls);
            let bytes = investigate_response(&thought(new_status));
            assert!(decode_investigation_response(&bytes, &context).is_err());
        }

        let pending = [item("item-1", QueueStatus::Pending)];
        let context = make_context(&[], &[], &pending, &calls);
        let pending_completion = response(
            InvestigationAction::Complete,
            &thought(QueueStatus::Pending),
        );
        assert!(decode_investigation_response(&pending_completion, &context).is_err());

        let observations = [observation(1, true)];
        let mut completed = item("item-1", QueueStatus::Complete);
        completed.evidence_turns = vec![1];
        let prior = [completed.clone()];
        let terminal_context = make_context(&observations, &[], &prior, &calls);
        let mut terminal_thought = thought(QueueStatus::Complete);
        terminal_thought.queue = vec![completed];
        let stable_completion = response(InvestigationAction::Complete, &terminal_thought);
        assert!(decode_investigation_response(&stable_completion, &terminal_context).is_ok());
    }

    #[test]
    fn oversized_responses_and_usage_overruns_fail() {
        let calls = [call(0)];
        let queue = [item("item-1", QueueStatus::Pending)];
        let mut context = make_context(&[], &[], &queue, &calls);
        let oversized = vec![b' '; MAX_INVESTIGATION_RESPONSE_BYTES + 1];
        assert!(decode_investigation_response(&oversized, &context).is_err());
        assert!(ScriptedInvestigationPlanner::new([oversized])
            .validate_script()
            .is_err());

        for (input_tokens, output_tokens) in [(101, 1), (1, 101)] {
            let mut over_budget = thought(QueueStatus::Active);
            over_budget.usage = Usage {
                input_tokens,
                output_tokens,
            };
            assert!(
                decode_investigation_response(&investigate_response(&over_budget), &context)
                    .is_err()
            );
        }
        context.remaining_usage = Usage {
            input_tokens: 0,
            output_tokens: 0,
        };
        assert!(decode_investigation_response(
            &investigate_response(&thought(QueueStatus::Active)),
            &context
        )
        .is_err());
    }

    #[test]
    fn valid_investigation_adapts_to_confirmed_observation_and_completes() {
        let calls = [call(0)];
        let initial_queue = [item("item-1", QueueStatus::Pending)];
        let initial_context = make_context(&[], &[], &initial_queue, &calls);

        let mut first_thought = thought(QueueStatus::Active);
        first_thought.hypotheses = vec![hypothesis("h1", HypothesisStatus::Open, vec![])];
        let first_bytes = investigate_response(&first_thought);
        let mut second_thought = thought(QueueStatus::Complete);
        second_thought.hypotheses = vec![hypothesis("h1", HypothesisStatus::Supported, vec![1])];
        second_thought.queue[0].evidence_turns = vec![1];
        let second_bytes = response(InvestigationAction::Complete, &second_thought);
        let mut planner = ScriptedInvestigationPlanner::new([first_bytes, second_bytes]);

        let first = planner.next_decision(&initial_context).unwrap();
        assert!(matches!(
            first.action,
            InvestigationAction::Investigate { call_index: 0, .. }
        ));
        let observations = [observation(1, true)];
        let adaptive_context = make_context(
            &observations,
            &first.thought.hypotheses,
            &first.thought.queue,
            &calls,
        );
        let second = planner.next_decision(&adaptive_context).unwrap();
        assert_eq!(second.action, InvestigationAction::Complete);
        assert_eq!(second.thought.queue[0].status, QueueStatus::Complete);
        assert_eq!(second.thought.queue[0].evidence_turns, vec![1]);
        assert_eq!(planner.decisions, 2);
    }
}
