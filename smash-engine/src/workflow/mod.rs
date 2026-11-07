//! M5 revoked-invitation product workflow. This module is independent of M2 admission.

mod oracle;
mod persist;
pub(crate) mod policy;
mod session;
mod step;

pub use oracle::{
    Assessment, Interpretation, RunRecord, StateSnapshot, StepRecord, WorkflowConclusion,
    WorkflowRunKind, WorkflowStep,
};
pub use persist::{verify, WorkflowManifest, WorkflowVerification};
pub use policy::{
    read_policy, WorkflowPolicy, REVOKED_INVITE_DRIVER_NAME, REVOKED_INVITE_DRIVER_SHA256,
    REVOKED_INVITE_ORACLE, REVOKED_INVITE_SCENARIO, SYNTHETIC_GUEST_CREDENTIAL_REFERENCE,
};
pub use session::run_from_path;
pub use crate::repro::error::ReproError as WorkflowError;
