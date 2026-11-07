//! Versioned dynamic regression oracle. Evaluation never executes or replays artifacts.

use crate::repro::linux::LinuxOutput;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use smash_core::execution::{ControlArtifact, ControlVariant, EvidenceState, ExecutionReceipt};
use std::path::Path;

pub const AUTHENTICATED_RETRY_ORACLE_VERSION: &str = "authenticated-retry-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopedReproductionVerdict {
    Reproduced,
    Inconclusive,
    ControlInvalid,
}
impl ScopedReproductionVerdict {
    pub fn reproduced(self) -> bool {
        self == Self::Reproduced
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlDecision {
    AsExpected,
    Inconclusive,
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleControlAssessment {
    pub control: ControlVariantWire,
    pub outcome: ControlDecision,
    pub expected_terminal: bool,
    pub artifact_sha256: String,
    pub oracle_version: String,
    pub omission: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlVariantWire {
    Broken,
    Fixed,
}
impl From<ControlVariant> for ControlVariantWire {
    fn from(value: ControlVariant) -> Self {
        match value {
            ControlVariant::Broken => Self::Broken,
            ControlVariant::Fixed => Self::Fixed,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedRegression {
    pub verdict: ScopedReproductionVerdict,
    pub oracle_version: String,
    pub controls: [OracleControlAssessment; 2],
    pub oracle_valid: bool,
    pub limitations: Vec<String>,
}
impl ScopedRegression {
    pub fn reproduced(&self) -> bool {
        self.verdict.reproduced() && self.oracle_valid
    }
}

/// Does not accept a clean control as evidence that a repository is safe.
pub fn evaluate_control(
    control: ControlVariant,
    artifact: &ControlArtifact,
    receipt: &ExecutionReceipt,
    output: &LinuxOutput,
) -> OracleControlAssessment {
    let wire = ControlVariantWire::from(control);
    let incomplete = || OracleControlAssessment {
        control: wire,
        outcome: ControlDecision::Inconclusive,
        expected_terminal: false,
        artifact_sha256: artifact.sha256.clone(),
        oracle_version: AUTHENTICATED_RETRY_ORACLE_VERSION.into(),
        omission: "terminal observation, declared output, cleanup, or control identity missing"
            .into(),
    };
    if receipt.artifact_sha256 != artifact.sha256
        || !output.contained
        || !receipt.output_bounded
        || !receipt.cleanup_completed
        || output.end.state != receipt.state
        || output.end.unresolved
        || output.resource_output > 65_536
        || output.end.state == EvidenceState::EnvironmentSetupFailed
        || output.end.state == EvidenceState::OutputLimitExceeded
    {
        return incomplete();
    }
    if wire == ControlVariantWire::Fixed && !matches!(receipt.state, EvidenceState::Succeeded) {
        return incomplete();
    }
    let expected_terminal = match wire {
        ControlVariantWire::Broken => receipt.state == EvidenceState::ReproductionFailed,
        ControlVariantWire::Fixed => receipt.state == EvidenceState::Succeeded,
    };
    if !expected_terminal || receipt.successful_exit == Some(wire == ControlVariantWire::Broken) {
        return OracleControlAssessment {
            control: wire,
            outcome: ControlDecision::Invalid,
            expected_terminal: false,
            artifact_sha256: artifact.sha256.clone(),
            oracle_version: AUTHENTICATED_RETRY_ORACLE_VERSION.into(),
            omission: "the control did not establish its required terminal behavior".into(),
        };
    }
    let Some(output) = output.declared_outputs.get(Path::new("result.json")) else {
        return incomplete();
    };
    let Ok(result) = serde_json::from_slice::<Value>(output) else {
        return incomplete();
    };
    let Some(object) = result.as_object() else {
        return incomplete();
    };
    let known = [
        "oracle_version",
        "target_tool",
        "control",
        "artifact_sha256",
        "observed_state",
        "expected_state",
    ];
    let valid = object.len() == known.len()
        && known.iter().all(|key| object.contains_key(*key))
        && result["oracle_version"] == AUTHENTICATED_RETRY_ORACLE_VERSION
        && result["target_tool"] == "authenticated-retry"
        && result["control"] == serde_json::to_value(wire).unwrap_or(Value::Null)
        && result["artifact_sha256"].as_str() == Some(artifact.sha256.as_str())
        && result["expected_state"] == "current-session";
    if !valid {
        return incomplete();
    }
    let mismatched = result["observed_state"] != result["expected_state"];
    let correct = match wire {
        ControlVariantWire::Broken => mismatched,
        ControlVariantWire::Fixed => !mismatched,
    };
    OracleControlAssessment {
        control: wire,
        outcome: if correct {
            ControlDecision::AsExpected
        } else {
            ControlDecision::Invalid
        },
        expected_terminal,
        artifact_sha256: artifact.sha256.clone(),
        oracle_version: AUTHENTICATED_RETRY_ORACLE_VERSION.into(),
        omission: "one declared fixture only; no exploitability or general security judgment"
            .into(),
    }
}

pub fn evaluate_pair(
    broken: OracleControlAssessment,
    fixed: OracleControlAssessment,
) -> ScopedRegression {
    let matched = broken.artifact_sha256 == fixed.artifact_sha256
        && broken.oracle_version == fixed.oracle_version
        && broken.oracle_version == AUTHENTICATED_RETRY_ORACLE_VERSION;
    let valid = matched
        && broken.outcome == ControlDecision::AsExpected
        && fixed.outcome == ControlDecision::AsExpected;
    ScopedRegression {
        verdict: if valid {
            ScopedReproductionVerdict::Reproduced
        } else if broken.outcome == ControlDecision::Invalid
            || fixed.outcome == ControlDecision::Invalid
        {
            ScopedReproductionVerdict::ControlInvalid
        } else {
            ScopedReproductionVerdict::Inconclusive
        },
        oracle_version: fixed.oracle_version.clone(),
        controls: [broken, fixed],
        oracle_valid: valid,
        limitations: vec![
            "Only a scoped policy violation was reproduced on two seeded local fixture controls."
                .into(),
            "This does not establish security, safety, exploitability, or production status."
                .into(),
            "Network effects, concurrent clients, and concurrent attackers were not exercised."
                .into(),
            "A clean fixed control is not a security certificate for the fixture.".into(),
        ],
    }
}
