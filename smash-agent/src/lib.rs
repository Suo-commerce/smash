//! Strict model-to-experiment boundary.
//!
//! Agent output is inert data. This crate has no filesystem, network, process,
//! or dispatch API. Executors must independently enforce their own authority,
//! path, command, timeout, and resource limits.

pub mod investigation;
pub mod protocol;
pub mod scripted;

pub use investigation::{
    decode_investigation_response, validate_investigation_context, CallDescriptor, Hypothesis,
    HypothesisStatus, InvestigationAction, InvestigationContext, InvestigationOutput,
    InvestigationPlanner, ObservationDescriptor, QueueItem, QueueStatus,
    ScriptedInvestigationPlanner, Thought, Usage, INVESTIGATION_SCHEMA_VERSION,
    MAX_INVESTIGATION_CALLS, MAX_INVESTIGATION_ITEMS, MAX_INVESTIGATION_RESPONSE_BYTES,
};
pub use protocol::{
    AgentAction, CompletionDraft, HypothesisDraft, Planner, PlannerContext, PlannerError,
    PlannerOutput,
};
pub use scripted::ScriptedPlanner;
