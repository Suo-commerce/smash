use super::policy::{HttpInvestigationPolicy, ReconInvestigationSeed, M4_INVESTIGATION_VERSION};
use crate::canonical::parse_no_duplicates;
use crate::http::campaign::{
    execute_read_call, verify_read_attempt, HttpAttemptEvidence, HttpCampaignError, HttpOutcome,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use smash_agent::investigation::{
    decode_investigation_response, Hypothesis, HypothesisStatus, InvestigationAction,
    InvestigationContext, InvestigationPlanner, ObservationDescriptor, QueueItem, QueueStatus,
    Thought, Usage, MAX_INVESTIGATION_ITEMS, MAX_INVESTIGATION_RESPONSE_BYTES,
};
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAX_STATE_BYTES: u64 = 1024 * 1024;
const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_JOURNAL_RECORDS: usize = MAX_INVESTIGATION_ITEMS * 2 + 2;

fn is_zero(value: &u32) -> bool {
    *value == 0
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationTerminal {
    Complete,
    NoProgress,
    BudgetExhausted,
    PlannerRejected,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InvestigationState {
    pub schema_version: u32,
    pub journal_entries: usize,
    pub journal_sha256: String,
    pub next_turn: u32,
    pub planner_turns: u32,
    /// Binds provenance that is not an M4 observation into journal replay.
    /// Omitted for legacy and unseeded sessions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recon_seed_sha256: Option<String>,
    pub hypotheses: Vec<Hypothesis>,
    pub queue: Vec<QueueItem>,
    pub observations: Vec<ObservationDescriptor>,
    pub usage: Usage,
    /// Persisted only for the additive no-progress budget; legacy snapshots
    /// deserialize as zero and replay with that budget disabled.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub consecutive_unproductive_turns: u32,
    /// A read may have been dispatched. No operation is permitted on resume.
    pub pending_selection: Option<InvestigationAction>,
    pub terminal: Option<InvestigationTerminal>,
}

impl InvestigationState {
    fn initial(policy: &HttpInvestigationPolicy) -> Result<Self, HttpCampaignError> {
        let recon_seed_sha256 = policy
            .recon_seed
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()?
            .map(|bytes| digest(&bytes));
        Ok(Self {
            schema_version: M4_INVESTIGATION_VERSION,
            journal_entries: 0,
            journal_sha256: digest(&[]),
            next_turn: 1,
            planner_turns: 0,
            recon_seed_sha256,
            hypotheses: policy.initial_hypotheses(),
            queue: policy.queue.clone(),
            observations: Vec::new(),
            usage: Usage {
                input_tokens: 0,
                output_tokens: 0,
            },
            consecutive_unproductive_turns: 0,
            pending_selection: None,
            terminal: None,
        })
    }

    pub fn all_items_complete(&self) -> bool {
        self.queue
            .iter()
            .all(|item| item.status == QueueStatus::Complete)
            && self.hypotheses.iter().all(|hypothesis| {
                matches!(
                    hypothesis.status,
                    HypothesisStatus::Supported | HypothesisStatus::Refuted
                )
            })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InvestigationAttempt {
    pub turn: u32,
    pub item_id: String,
    pub call_index: usize,
    pub call: HttpAttemptEvidence,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "record", rename_all = "snake_case", deny_unknown_fields)]
pub enum InvestigationRecord {
    Decision {
        turn: u32,
        response_file: String,
        response_sha256: String,
        action: InvestigationAction,
        thought: Thought,
    },
    Observation {
        turn: u32,
        item_id: String,
        call_index: usize,
        call: HttpAttemptEvidence,
    },
    Terminal {
        turn: u32,
        terminal: InvestigationTerminal,
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedInvestigation {
    pub policy: HttpInvestigationPolicy,
    pub state: InvestigationState,
    pub attempts: Vec<InvestigationAttempt>,
    pub responses: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationRunStatus {
    Complete,
    NoProgress,
    BudgetExhausted,
    PlannerRejected,
    Unresolved,
    AlreadyComplete,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvestigationRunReport {
    pub schema_version: u32,
    pub status: InvestigationRunStatus,
    pub path: PathBuf,
    pub planner_turns: u32,
    pub requests: usize,
    pub consecutive_unproductive_turns: u32,
    pub all_items_complete: bool,
    pub replayed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct InvestigationVerificationReport<'a> {
    pub schema_version: u32,
    pub valid: bool,
    pub terminal: &'a Option<InvestigationTerminal>,
    pub planner_turns: u32,
    pub requests: usize,
    pub pending_selection: bool,
    pub consecutive_unproductive_turns: u32,
    pub all_items_complete: bool,
    pub hypotheses: &'a [Hypothesis],
    pub recon_seed: &'a Option<ReconInvestigationSeed>,
    pub attempts: &'a [InvestigationAttempt],
    pub network: &'static str,
    pub scope: &'static str,
}

pub fn verification_report(
    verified: &VerifiedInvestigation,
) -> InvestigationVerificationReport<'_> {
    InvestigationVerificationReport {
        schema_version: 1,
        valid: true,
        terminal: &verified.state.terminal,
        planner_turns: verified.state.planner_turns,
        requests: verified.attempts.len(),
        pending_selection: verified.state.pending_selection.is_some(),
        consecutive_unproductive_turns: verified.state.consecutive_unproductive_turns,
        all_items_complete: verified.state.all_items_complete(),
        hypotheses: &verified.state.hypotheses,
        recon_seed: &verified.policy.recon_seed,
        attempts: &verified.attempts,
        network: "not used",
        scope: "offline consistency of pre-admitted read observations; no target authenticity, security, exploitability, or exhaustive-coverage claim",
    }
}

pub fn pending_path(output: &Path) -> Result<PathBuf, HttpCampaignError> {
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| HttpCampaignError("investigation output requires a file name".into()))?;
    Ok(output.with_file_name(format!(".smash-m4-{name}-pending")))
}

struct Store {
    root: PathBuf,
}

impl Store {
    fn create(output: &Path, policy: &HttpInvestigationPolicy) -> Result<Self, HttpCampaignError> {
        let root = pending_path(output)?;
        if exists(output) || exists(&root) {
            return Err(HttpCampaignError(
                "investigation output or pending session already exists; use resume for pending work"
                    .into(),
            ));
        }
        create_private_dir(&root)?;
        create_private_dir(&root.join("responses"))?;
        let store = Self { root };
        store.write_new(
            &store.root.join("policy.json"),
            &serde_json::to_vec(policy)?,
        )?;
        store.write_new(&store.root.join("journal.jsonl"), &[])?;
        store.write_state(&InvestigationState::initial(policy)?)?;
        sync_dir(&store.root)?;
        Ok(store)
    }

    fn open_pending(output: &Path) -> Result<Self, HttpCampaignError> {
        Ok(Self {
            root: pending_path(output)?,
        })
    }

    fn raw_response(&self, turn: u32, bytes: &[u8], sha256: &str) -> Result<(), HttpCampaignError> {
        if bytes.len() > MAX_INVESTIGATION_RESPONSE_BYTES || digest(bytes) != sha256 {
            return Err(HttpCampaignError(
                "planner response identity did not match the accepted decision".into(),
            ));
        }
        self.write_new(&self.response_path(turn), bytes)?;
        sync_dir(&self.root.join("responses"))
    }

    fn response_path(&self, turn: u32) -> PathBuf {
        self.root.join("responses").join(format!("{turn:08}.json"))
    }

    fn append(
        &self,
        record: &InvestigationRecord,
        state: &mut InvestigationState,
    ) -> Result<(), HttpCampaignError> {
        if state.journal_entries >= MAX_JOURNAL_RECORDS {
            return Err(HttpCampaignError(
                "investigation journal record ceiling reached".into(),
            ));
        }
        let mut bytes = serde_json::to_vec(record)?;
        bytes.push(b'\n');
        let mut options = fs::OpenOptions::new();
        options.append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(self.root.join("journal.jsonl"))?;
        if file.metadata()?.len().saturating_add(bytes.len() as u64) > MAX_JOURNAL_BYTES {
            return Err(HttpCampaignError(
                "investigation journal byte ceiling reached".into(),
            ));
        }
        file.write_all(&bytes)?;
        file.sync_all()?;
        state.journal_sha256 = digest(&read_bounded(
            &self.root.join("journal.jsonl"),
            MAX_JOURNAL_BYTES,
        )?);
        state.journal_entries += 1;
        self.write_state(state)
    }

    fn write_state(&self, state: &InvestigationState) -> Result<(), HttpCampaignError> {
        let bytes = serde_json::to_vec(state)?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(HttpCampaignError(
                "investigation state exceeds its byte ceiling".into(),
            ));
        }
        let next = self.root.join("state.json.next");
        if exists(&next) {
            return Err(HttpCampaignError(
                "an incomplete investigation state write requires manual inspection".into(),
            ));
        }
        self.write_new(&next, &bytes)?;
        fs::rename(&next, self.root.join("state.json"))?;
        sync_dir(&self.root)
    }

    fn write_new(&self, path: &Path, bytes: &[u8]) -> Result<(), HttpCampaignError> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn publish(&self, output: &Path, state: &InvestigationState) -> Result<(), HttpCampaignError> {
        if state.terminal.is_none() || exists(output) {
            return Err(HttpCampaignError(
                "only a terminal investigation can publish to a new output".into(),
            ));
        }
        if verify_session(&self.root)?.state != *state {
            return Err(HttpCampaignError(
                "investigation state changed before publication".into(),
            ));
        }
        fs::rename(&self.root, output)?;
        if let Some(parent) = output.parent() {
            sync_dir(parent)?;
        }
        Ok(())
    }
}

pub fn start_investigation<P, F>(
    output: &Path,
    policy: &HttpInvestigationPolicy,
    planner: &mut P,
    credential: F,
) -> Result<InvestigationRunReport, HttpCampaignError>
where
    P: InvestigationPlanner,
    F: FnMut(&str) -> Option<String>,
{
    policy.validate()?;
    let store = Store::create(output, policy)?;
    let state = InvestigationState::initial(policy)?;
    let report = drive(
        &store,
        policy,
        state,
        Vec::new(),
        Vec::new(),
        planner,
        credential,
    )?;
    store.publish(output, &report.1)?;
    Ok(run_report(
        InvestigationRunStatus::from_terminal(report.1.terminal.as_ref()),
        output.to_path_buf(),
        &report.1,
        report.0,
    ))
}

pub fn resume_investigation<P, F>(
    output: &Path,
    policy: &HttpInvestigationPolicy,
    planner: &mut P,
    credential: F,
) -> Result<InvestigationRunReport, HttpCampaignError>
where
    P: InvestigationPlanner,
    F: FnMut(&str) -> Option<String>,
{
    policy.validate()?;
    if exists(output) {
        let verified = verify_session(output)?;
        if verified.policy != *policy || verified.state.terminal.is_none() {
            return Err(HttpCampaignError(
                "existing investigation identity or terminal state mismatch".into(),
            ));
        }
        return Ok(run_report(
            InvestigationRunStatus::AlreadyComplete,
            output.to_path_buf(),
            &verified.state,
            verified.attempts,
        ));
    }
    let store = Store::open_pending(output)?;
    let verified = verify_session(&store.root)?;
    if verified.policy != *policy {
        return Err(HttpCampaignError(
            "investigation policy differs from its admitted pending session".into(),
        ));
    }
    if verified.state.pending_selection.is_some() {
        return Ok(run_report(
            InvestigationRunStatus::Unresolved,
            store.root,
            &verified.state,
            verified.attempts,
        ));
    }
    if verified.state.terminal.is_some() {
        store.publish(output, &verified.state)?;
        return Ok(run_report(
            InvestigationRunStatus::from_terminal(verified.state.terminal.as_ref()),
            output.to_path_buf(),
            &verified.state,
            verified.attempts,
        ));
    }
    planner
        .restore(&verified.responses)
        .map_err(|error| HttpCampaignError(format!("investigation resume refused: {error}")))?;
    let report = drive(
        &store,
        policy,
        verified.state,
        verified.attempts,
        verified.responses,
        planner,
        credential,
    )?;
    store.publish(output, &report.1)?;
    Ok(run_report(
        InvestigationRunStatus::from_terminal(report.1.terminal.as_ref()),
        output.to_path_buf(),
        &report.1,
        report.0,
    ))
}

impl InvestigationRunStatus {
    fn from_terminal(terminal: Option<&InvestigationTerminal>) -> Self {
        match terminal {
            Some(InvestigationTerminal::Complete) => Self::Complete,
            Some(InvestigationTerminal::NoProgress) => Self::NoProgress,
            Some(InvestigationTerminal::BudgetExhausted) => Self::BudgetExhausted,
            Some(InvestigationTerminal::PlannerRejected) => Self::PlannerRejected,
            None => Self::Unresolved,
        }
    }
}

fn run_report(
    status: InvestigationRunStatus,
    path: PathBuf,
    state: &InvestigationState,
    attempts: Vec<InvestigationAttempt>,
) -> InvestigationRunReport {
    InvestigationRunReport {
        schema_version: M4_INVESTIGATION_VERSION,
        status,
        path,
        planner_turns: state.planner_turns,
        requests: attempts.len(),
        consecutive_unproductive_turns: state.consecutive_unproductive_turns,
        all_items_complete: state.all_items_complete(),
        replayed: false,
    }
}

#[allow(clippy::too_many_arguments)]
fn drive<P, F>(
    store: &Store,
    policy: &HttpInvestigationPolicy,
    mut state: InvestigationState,
    mut attempts: Vec<InvestigationAttempt>,
    mut responses: Vec<Vec<u8>>,
    planner: &mut P,
    mut credential: F,
) -> Result<(Vec<InvestigationAttempt>, InvestigationState), HttpCampaignError>
where
    P: InvestigationPlanner,
    F: FnMut(&str) -> Option<String>,
{
    loop {
        if state.terminal.is_some() {
            return Ok((attempts, state));
        }
        if state.pending_selection.is_some() {
            return Err(HttpCampaignError(
                "a persisted selected read is unresolved and cannot be replayed".into(),
            ));
        }
        if state.planner_turns >= policy.budgets.max_planner_turns {
            append_terminal(
                store,
                &mut state,
                InvestigationTerminal::BudgetExhausted,
                "planner-turn budget exhausted before a completion decision",
            )?;
            continue;
        }
        if attempts.len() >= policy.budgets.max_calls as usize
            && state.planner_turns as usize > attempts.len()
        {
            // An accepted over-budget selection is terminal even if the process
            // stopped between its decision and terminal journal records.
            append_terminal(
                store,
                &mut state,
                InvestigationTerminal::BudgetExhausted,
                "read-call budget exhausted before the selected read could execute",
            )?;
            continue;
        }
        if no_progress_limit_reached(policy.budgets.max_consecutive_unproductive_turns, &state) {
            append_terminal(
                store,
                &mut state,
                InvestigationTerminal::NoProgress,
                "consecutive unproductive turns reached their bounded limit",
            )?;
            continue;
        }
        let calls = policy.call_descriptors();
        let context = InvestigationContext {
            run_id: &policy.campaign.run_id,
            next_turn: state.next_turn,
            calls: &calls,
            observations: &state.observations,
            hypotheses: &state.hypotheses,
            queue: &state.queue,
            remaining_usage: remaining_usage(policy, &state)?,
        };
        let output = match planner.next_decision(&context) {
            Ok(output) => output,
            Err(error) => {
                append_terminal(
                    store,
                    &mut state,
                    InvestigationTerminal::PlannerRejected,
                    &diagnostic(&error.to_string()),
                )?;
                continue;
            }
        };
        let accepted = decode_investigation_response(&output.response_bytes, &context)
            .map_err(|error| error.0)
            .and_then(|(action, thought)| {
                if action == output.action
                    && thought == output.thought
                    && output.response_sha256 == digest(&output.response_bytes)
                {
                    Ok(())
                } else {
                    Err("planner decision differs from its raw response or digest".into())
                }
            });
        if let Err(error) = accepted {
            append_terminal(
                store,
                &mut state,
                InvestigationTerminal::PlannerRejected,
                &diagnostic(&error),
            )?;
            continue;
        }
        store.raw_response(
            state.next_turn,
            &output.response_bytes,
            &output.response_sha256,
        )?;
        responses.push(output.response_bytes);
        let turn = state.next_turn;
        apply_decision_progress(
            policy.budgets.max_consecutive_unproductive_turns,
            &mut state,
            &output.thought,
        )?;
        state.hypotheses = output.thought.hypotheses.clone();
        state.queue = output.thought.queue.clone();
        state.usage.input_tokens = state
            .usage
            .input_tokens
            .checked_add(output.thought.usage.input_tokens)
            .ok_or_else(|| HttpCampaignError("input token total overflow".into()))?;
        state.usage.output_tokens = state
            .usage
            .output_tokens
            .checked_add(output.thought.usage.output_tokens)
            .ok_or_else(|| HttpCampaignError("output token total overflow".into()))?;
        state.planner_turns += 1;
        if matches!(output.action, InvestigationAction::Investigate { .. }) {
            state.pending_selection = Some(output.action.clone());
        }
        store.append(
            &InvestigationRecord::Decision {
                turn,
                response_file: format!("{turn:08}.json"),
                response_sha256: output.response_sha256,
                action: output.action.clone(),
                thought: output.thought,
            },
            &mut state,
        )?;

        let InvestigationAction::Investigate {
            item_id,
            call_index,
        } = output.action
        else {
            append_terminal(
                store,
                &mut state,
                InvestigationTerminal::Complete,
                "all admitted queue items reached a terminal planner state",
            )?;
            continue;
        };
        if attempts.len() >= policy.budgets.max_calls as usize {
            // The accepted but unexecuted selection remains in the journal. It
            // establishes why the budget stopped the run, not that it was sent.
            state.pending_selection = None;
            store.write_state(&state)?;
            append_terminal(
                store,
                &mut state,
                InvestigationTerminal::BudgetExhausted,
                "read-call budget exhausted before the selected read could execute",
            )?;
            continue;
        }
        let call = execute_read_call(
            &policy.campaign,
            call_index,
            attempts.len(),
            &mut credential,
        )?;
        verify_read_attempt(&policy.campaign, call_index, attempts.len(), &call)?;
        state.observations.push(ObservationDescriptor {
            sequence: turn,
            item_id: item_id.clone(),
            call_index,
            observed: call.outcome == HttpOutcome::Observed,
        });
        state.pending_selection = None;
        apply_observation_progress(
            policy.budgets.max_consecutive_unproductive_turns,
            &mut state,
            call.outcome == HttpOutcome::Observed,
        );
        state.next_turn = state
            .next_turn
            .checked_add(1)
            .ok_or_else(|| HttpCampaignError("investigation turn overflow".into()))?;
        store.append(
            &InvestigationRecord::Observation {
                turn,
                item_id: item_id.clone(),
                call_index,
                call: call.clone(),
            },
            &mut state,
        )?;
        attempts.push(InvestigationAttempt {
            turn,
            item_id,
            call_index,
            call,
        });
    }
}

fn append_terminal(
    store: &Store,
    state: &mut InvestigationState,
    terminal: InvestigationTerminal,
    reason: &str,
) -> Result<(), HttpCampaignError> {
    state.terminal = Some(terminal.clone());
    store.append(
        &InvestigationRecord::Terminal {
            turn: state.next_turn,
            terminal,
            reason: reason.to_owned(),
        },
        state,
    )
}

fn remaining_usage(
    policy: &HttpInvestigationPolicy,
    state: &InvestigationState,
) -> Result<Usage, HttpCampaignError> {
    let limits = policy.usage_limit();
    Ok(Usage {
        input_tokens: limits
            .input_tokens
            .checked_sub(state.usage.input_tokens)
            .ok_or_else(|| HttpCampaignError("input usage exceeds its budget".into()))?,
        output_tokens: limits
            .output_tokens
            .checked_sub(state.usage.output_tokens)
            .ok_or_else(|| HttpCampaignError("output usage exceeds its budget".into()))?,
    })
}

fn no_progress_limit_reached(limit: Option<u32>, state: &InvestigationState) -> bool {
    limit.is_some_and(|limit| state.consecutive_unproductive_turns >= limit)
}

fn apply_decision_progress(
    limit: Option<u32>,
    state: &mut InvestigationState,
    thought: &Thought,
) -> Result<(), HttpCampaignError> {
    if limit.is_none() {
        return Ok(());
    }
    let status_transition = state
        .hypotheses
        .iter()
        .zip(&thought.hypotheses)
        .any(|(before, after)| before.status != after.status)
        || state
            .queue
            .iter()
            .zip(&thought.queue)
            .any(|(before, after)| before.status != after.status);
    state.consecutive_unproductive_turns = if status_transition {
        0
    } else {
        state
            .consecutive_unproductive_turns
            .checked_add(1)
            .ok_or_else(|| HttpCampaignError("consecutive unproductive turn overflow".into()))?
    };
    Ok(())
}

fn apply_observation_progress(limit: Option<u32>, state: &mut InvestigationState, observed: bool) {
    if observed && limit.is_some() {
        state.consecutive_unproductive_turns = 0;
    }
}

fn diagnostic(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .filter(|character| !character.is_control())
        .take(256)
        .collect();
    if cleaned.is_empty() {
        "planner rejected without diagnostic".into()
    } else {
        cleaned
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn create_private_dir(path: &Path) -> Result<(), HttpCampaignError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    #[cfg(not(unix))]
    fs::create_dir(path)?;
    Ok(())
}

fn sync_dir(path: &Path) -> Result<(), HttpCampaignError> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, HttpCampaignError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(HttpCampaignError(
            "investigation input is not a bounded regular non-symlink file".into(),
        ));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(HttpCampaignError(
            "investigation input exceeds its byte ceiling".into(),
        ));
    }
    Ok(bytes)
}

fn parse<T: for<'a> Deserialize<'a>>(bytes: &[u8]) -> Result<T, HttpCampaignError> {
    let value = parse_no_duplicates(bytes)
        .map_err(|_| HttpCampaignError("investigation file is not strict JSON".into()))?;
    serde_json::from_value(value)
        .map_err(|_| HttpCampaignError("investigation file schema mismatch".into()))
}

/// Validate every admissible transition without reading a target, environment,
/// executor, credential, or response body. The response bytes are replayed only
/// through the inert agent decoder to re-establish their original decisions.
pub fn verify_session(root: &Path) -> Result<VerifiedInvestigation, HttpCampaignError> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(HttpCampaignError(
            "investigation session must be a regular directory".into(),
        ));
    }
    let entries = fs::read_dir(root)?
        .map(|entry| {
            entry?
                .file_name()
                .into_string()
                .map_err(|_| HttpCampaignError("investigation path is not UTF-8".into()))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = ["journal.jsonl", "policy.json", "responses", "state.json"]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if entries != expected {
        return Err(HttpCampaignError(
            "investigation session contains missing or unreferenced files".into(),
        ));
    }
    let response_dir = root.join("responses");
    let response_metadata = fs::symlink_metadata(&response_dir)?;
    if !response_metadata.is_dir() || response_metadata.file_type().is_symlink() {
        return Err(HttpCampaignError(
            "investigation responses must be a regular directory".into(),
        ));
    }
    let policy_bytes = read_bounded(
        &root.join("policy.json"),
        super::policy::MAX_INVESTIGATION_POLICY_BYTES,
    )?;
    let policy: HttpInvestigationPolicy = parse(&policy_bytes)?;
    if serde_json::to_vec(&policy)? != policy_bytes {
        return Err(HttpCampaignError(
            "investigation policy is not its exact admitted encoding".into(),
        ));
    }
    policy.validate()?;
    let disk_state: InvestigationState =
        parse(&read_bounded(&root.join("state.json"), MAX_STATE_BYTES)?)?;
    let journal = read_bounded(&root.join("journal.jsonl"), MAX_JOURNAL_BYTES)?;
    if !journal.is_empty() && !journal.ends_with(b"\n") {
        return Err(HttpCampaignError(
            "investigation journal has an incomplete final record".into(),
        ));
    }
    let mut records = Vec::new();
    for line in journal.split(|byte| *byte == b'\n') {
        if !line.is_empty() {
            records.push(parse::<InvestigationRecord>(line)?);
        }
    }
    if records.len() > MAX_JOURNAL_RECORDS {
        return Err(HttpCampaignError(
            "investigation journal record ceiling exceeded".into(),
        ));
    }

    let mut state = InvestigationState::initial(&policy)?;
    let mut attempts = Vec::<InvestigationAttempt>::new();
    let mut responses = Vec::<Vec<u8>>::new();
    let mut response_files = BTreeSet::new();
    let calls = policy.call_descriptors();
    for (record_index, record) in records.iter().enumerate() {
        match record {
            InvestigationRecord::Decision {
                turn,
                response_file,
                response_sha256,
                action,
                thought,
            } => {
                if *turn != state.next_turn
                    || state.terminal.is_some()
                    || state.pending_selection.is_some()
                    || state.planner_turns >= policy.budgets.max_planner_turns
                    || no_progress_limit_reached(
                        policy.budgets.max_consecutive_unproductive_turns,
                        &state,
                    )
                    || *response_file != format!("{turn:08}.json")
                {
                    return Err(HttpCampaignError(
                        "invalid investigation decision transition".into(),
                    ));
                }
                let bytes = read_bounded(
                    &root.join("responses").join(response_file),
                    MAX_INVESTIGATION_RESPONSE_BYTES as u64,
                )?;
                if digest(&bytes) != *response_sha256 {
                    return Err(HttpCampaignError(
                        "investigation response digest mismatch".into(),
                    ));
                }
                let context = InvestigationContext {
                    run_id: &policy.campaign.run_id,
                    next_turn: state.next_turn,
                    calls: &calls,
                    observations: &state.observations,
                    hypotheses: &state.hypotheses,
                    queue: &state.queue,
                    remaining_usage: remaining_usage(&policy, &state)?,
                };
                let (decoded_action, decoded_thought) =
                    decode_investigation_response(&bytes, &context)
                        .map_err(|error| HttpCampaignError(error.0))?;
                if decoded_action != *action || decoded_thought != *thought {
                    return Err(HttpCampaignError(
                        "investigation journal differs from its planner response".into(),
                    ));
                }
                apply_decision_progress(
                    policy.budgets.max_consecutive_unproductive_turns,
                    &mut state,
                    thought,
                )?;
                state.hypotheses = thought.hypotheses.clone();
                state.queue = thought.queue.clone();
                state.usage.input_tokens = state
                    .usage
                    .input_tokens
                    .checked_add(thought.usage.input_tokens)
                    .ok_or_else(|| HttpCampaignError("input token total overflow".into()))?;
                state.usage.output_tokens = state
                    .usage
                    .output_tokens
                    .checked_add(thought.usage.output_tokens)
                    .ok_or_else(|| HttpCampaignError("output token total overflow".into()))?;
                if state.usage.input_tokens > policy.budgets.max_input_tokens
                    || state.usage.output_tokens > policy.budgets.max_output_tokens
                {
                    return Err(HttpCampaignError(
                        "investigation cumulative usage budget exceeded".into(),
                    ));
                }
                state.planner_turns += 1;
                state.pending_selection = match action {
                    InvestigationAction::Investigate { .. }
                        if attempts.len() < policy.budgets.max_calls as usize =>
                    {
                        Some(action.clone())
                    }
                    _ => None,
                };
                responses.push(bytes);
                if !response_files.insert(response_file.clone()) {
                    return Err(HttpCampaignError(
                        "investigation decisions must reference distinct responses".into(),
                    ));
                }
                state.journal_entries += 1;
                let expected_terminal = match action {
                    InvestigationAction::Complete => Some(InvestigationTerminal::Complete),
                    InvestigationAction::Investigate { .. }
                        if attempts.len() >= policy.budgets.max_calls as usize =>
                    {
                        Some(InvestigationTerminal::BudgetExhausted)
                    }
                    InvestigationAction::Investigate { .. } => None,
                };
                if let Some(expected_terminal) = expected_terminal {
                    let terminal_exists = matches!(
                        records.get(record_index + 1),
                        Some(InvestigationRecord::Terminal {
                            turn: terminal_turn,
                            terminal,
                            ..
                        }) if terminal_turn == turn && *terminal == expected_terminal
                    );
                    if !terminal_exists
                        && (matches!(action, InvestigationAction::Complete)
                            || record_index + 1 != records.len())
                    {
                        return Err(HttpCampaignError(
                            "terminal decision lacks its terminal record".into(),
                        ));
                    }
                }
            }
            InvestigationRecord::Observation {
                turn,
                item_id,
                call_index,
                call,
            } => {
                let expected = InvestigationAction::Investigate {
                    item_id: item_id.clone(),
                    call_index: *call_index,
                };
                if *turn != state.next_turn
                    || state.terminal.is_some()
                    || state.pending_selection.as_ref() != Some(&expected)
                    || attempts.len() != state.observations.len()
                    || attempts.len() >= policy.budgets.max_calls as usize
                {
                    return Err(HttpCampaignError(
                        "invalid investigation observation transition".into(),
                    ));
                }
                verify_read_attempt(&policy.campaign, *call_index, *turn as usize - 1, call)?;
                attempts.push(InvestigationAttempt {
                    turn: *turn,
                    item_id: item_id.clone(),
                    call_index: *call_index,
                    call: call.clone(),
                });
                state.observations.push(ObservationDescriptor {
                    sequence: *turn,
                    item_id: item_id.clone(),
                    call_index: *call_index,
                    observed: call.outcome == HttpOutcome::Observed,
                });
                state.pending_selection = None;
                apply_observation_progress(
                    policy.budgets.max_consecutive_unproductive_turns,
                    &mut state,
                    call.outcome == HttpOutcome::Observed,
                );
                state.next_turn += 1;
                state.journal_entries += 1;
            }
            InvestigationRecord::Terminal {
                turn,
                terminal,
                reason,
            } => {
                if *turn != state.next_turn
                    || state.terminal.is_some()
                    || state.pending_selection.is_some()
                    || record_index + 1 != records.len()
                    || reason.is_empty()
                    || reason.len() > 1024
                    || reason.chars().any(char::is_control)
                {
                    return Err(HttpCampaignError(
                        "invalid investigation terminal transition".into(),
                    ));
                }
                match terminal {
                    InvestigationTerminal::Complete => {
                        if !matches!(
                            records.get(record_index.wrapping_sub(1)),
                            Some(InvestigationRecord::Decision {
                                turn: decision_turn,
                                action: InvestigationAction::Complete,
                                ..
                            }) if decision_turn == turn
                        ) {
                            return Err(HttpCampaignError(
                                "complete terminal lacks its completion decision".into(),
                            ));
                        }
                    }
                    InvestigationTerminal::BudgetExhausted => {
                        let turn_limit = state.planner_turns >= policy.budgets.max_planner_turns;
                        let call_limit = attempts.len() >= policy.budgets.max_calls as usize
                            && matches!(
                                records.get(record_index.wrapping_sub(1)),
                                Some(InvestigationRecord::Decision {
                                    turn: decision_turn,
                                    action: InvestigationAction::Investigate { .. },
                                    ..
                                }) if decision_turn == turn
                            );
                        if !turn_limit && !call_limit {
                            return Err(HttpCampaignError(
                                "budget-exhausted terminal has no exhausted budget".into(),
                            ));
                        }
                    }
                    InvestigationTerminal::NoProgress => {
                        if state.planner_turns >= policy.budgets.max_planner_turns
                            || !no_progress_limit_reached(
                                policy.budgets.max_consecutive_unproductive_turns,
                                &state,
                            )
                            || !matches!(
                                records.get(record_index.wrapping_sub(1)),
                                Some(InvestigationRecord::Observation {
                                    turn: observation_turn,
                                    ..
                                }) if observation_turn + 1 == *turn
                            )
                        {
                            return Err(HttpCampaignError(
                                "invalid no-progress terminal transition".into(),
                            ));
                        }
                    }
                    InvestigationTerminal::PlannerRejected => {
                        if no_progress_limit_reached(
                            policy.budgets.max_consecutive_unproductive_turns,
                            &state,
                        ) {
                            return Err(HttpCampaignError(
                                "planner-rejected terminal follows a reached no-progress limit"
                                    .into(),
                            ));
                        }
                    }
                }
                state.terminal = Some(terminal.clone());
                state.journal_entries += 1;
            }
        }
    }
    state.journal_sha256 = digest(&journal);
    if state != disk_state {
        return Err(HttpCampaignError(
            "investigation state snapshot differs from journal replay".into(),
        ));
    }
    let actual_response_files = fs::read_dir(root.join("responses"))?
        .map(|entry| {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(HttpCampaignError(
                    "investigation response is not a regular file".into(),
                ));
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| HttpCampaignError("response file name is not UTF-8".into()))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if actual_response_files != response_files || responses.len() != state.planner_turns as usize {
        return Err(HttpCampaignError(
            "investigation response file set does not match decisions".into(),
        ));
    }
    Ok(VerifiedInvestigation {
        policy,
        state,
        attempts,
        responses,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn state() -> InvestigationState {
        InvestigationState {
            schema_version: M4_INVESTIGATION_VERSION,
            journal_entries: 0,
            journal_sha256: digest(&[]),
            next_turn: 1,
            planner_turns: 0,
            recon_seed_sha256: None,
            hypotheses: Vec::new(),
            queue: vec![QueueItem {
                item_id: "item-1".into(),
                purpose: "Exercise bounded no-progress transitions".into(),
                allowed_calls: vec![0],
                status: QueueStatus::Pending,
                evidence_turns: Vec::new(),
            }],
            observations: Vec::new(),
            usage: Usage {
                input_tokens: 0,
                output_tokens: 0,
            },
            consecutive_unproductive_turns: 0,
            pending_selection: None,
            terminal: None,
        }
    }

    fn repeated_thought(state: &InvestigationState) -> Thought {
        Thought {
            summary: "Prose alone is not progress".into(),
            hypotheses: state.hypotheses.clone(),
            queue: state.queue.clone(),
            usage: Usage {
                input_tokens: 1,
                output_tokens: 1,
            },
        }
    }

    #[test]
    fn no_progress_counts_unchanged_decisions_and_resets_only_on_observation() {
        let mut state = state();
        let mut thought = repeated_thought(&state);
        apply_decision_progress(Some(2), &mut state, &thought).unwrap();
        assert_eq!(state.consecutive_unproductive_turns, 1);
        assert!(!no_progress_limit_reached(Some(2), &state));

        thought.summary = "Changed text and usage still do not constitute progress".into();
        thought.usage.input_tokens = 2;
        apply_decision_progress(Some(2), &mut state, &thought).unwrap();
        assert_eq!(state.consecutive_unproductive_turns, 2);
        assert!(no_progress_limit_reached(Some(2), &state));
        apply_observation_progress(Some(2), &mut state, false);
        assert_eq!(state.consecutive_unproductive_turns, 2);
        apply_observation_progress(Some(2), &mut state, true);
        assert_eq!(state.consecutive_unproductive_turns, 0);
    }

    #[test]
    fn hypothesis_and_queue_status_transitions_each_reset_no_progress() {
        let mut state = state();
        state.hypotheses.push(Hypothesis {
            hypothesis_id: "hypothesis-1".into(),
            statement: "Exercise a validated hypothesis status transition".into(),
            status: HypothesisStatus::Open,
            evidence_turns: Vec::new(),
        });
        let mut thought = repeated_thought(&state);
        thought.hypotheses[0].status = HypothesisStatus::Inconclusive;
        state.consecutive_unproductive_turns = 2;
        apply_decision_progress(Some(2), &mut state, &thought).unwrap();
        assert_eq!(state.consecutive_unproductive_turns, 0);

        let mut thought = repeated_thought(&state);
        thought.queue[0].status = QueueStatus::Active;
        state.consecutive_unproductive_turns = 2;
        apply_decision_progress(Some(2), &mut state, &thought).unwrap();
        assert_eq!(state.consecutive_unproductive_turns, 0);
    }

    #[test]
    fn legacy_sessions_keep_the_no_progress_control_disabled_and_zero_omitted() {
        let mut state = state();
        let thought = repeated_thought(&state);
        apply_decision_progress(None, &mut state, &thought).unwrap();
        apply_observation_progress(None, &mut state, false);
        assert_eq!(state.consecutive_unproductive_turns, 0);
        state.consecutive_unproductive_turns = u32::MAX;
        assert!(!no_progress_limit_reached(None, &state));

        state.consecutive_unproductive_turns = 0;
        let encoded = serde_json::to_value(&state).unwrap();
        assert!(encoded.get("consecutive_unproductive_turns").is_none());
        let mut legacy = encoded.as_object().unwrap().clone();
        legacy.remove("consecutive_unproductive_turns");
        let decoded: InvestigationState = serde_json::from_value(Value::Object(legacy)).unwrap();
        assert_eq!(decoded.consecutive_unproductive_turns, 0);
    }
}
