use crate::Options;
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use smash_engine::repro::error::ReproError;
use smash_engine::workflow::{run_from_path, verify, WorkflowConclusion};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[derive(Debug)]
pub(super) struct CommandError {
    pub code: i32,
    pub message: String,
}
impl CommandError {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: message.into(),
        }
    }
}
impl From<ReproError> for CommandError {
    fn from(error: ReproError) -> Self {
        Self {
            code: 2,
            message: error.to_string(),
        }
    }
}

pub(super) fn command(name: &str, options: Options) -> Result<(i32, String), CommandError> {
    if !options.unnamed.is_empty()
        || options.target.is_some()
        || options.repo.is_some()
        || options.script.is_some()
        || options.max_experiments.is_some()
        || options.max_queries.is_some()
        || options.run_id.is_some()
        || options.execute_fixture_mutations
    {
        return Err(CommandError::usage(
            "workflow command received arguments for a different subsystem",
        ));
    }
    match name {
        "workflow-repro" => {
            if options.bundle.is_some() {
                return Err(CommandError::usage("workflow-repro requires --policy FILE --out DIRECTORY --execute-fixture-workflow"));
            }
            let policy = options
                .policy
                .ok_or_else(|| CommandError::usage("--policy is required"))?;
            let out = options
                .out
                .ok_or_else(|| CommandError::usage("--out is required"))?;
            let cancel = Arc::new(AtomicBool::new(false));
            for signal in [SIGINT, SIGTERM] {
                signal_hook::flag::register(signal, Arc::clone(&cancel)).map_err(|error| {
                    CommandError::usage(format!("could not install cancellation handler: {error}"))
                })?;
            }
            let manifest = run_from_path(&policy, &out, options.execute_fixture_workflow, &cancel)
                .map_err(CommandError::from)?;
            let code = match manifest.conclusion {
                WorkflowConclusion::Confirmed => 0,
                WorkflowConclusion::NoEffect => 1,
                WorkflowConclusion::EnvironmentManualReview
                | WorkflowConclusion::InterpretationFailed => 2,
            };
            let conclusion = manifest.conclusion.slug();
            if options.json {
                Ok((
                    code,
                    display(
                        serde_json::json!({
                            "bundle_version": manifest.bundle_version,
                            "conclusion": conclusion,
                            "manifest": manifest,
                            "scope": "contained synthetic product workflow only; not a vulnerability or production-security claim",
                            "verification": "typed effects and cleanup; no ambient target or real credentials",
                        }),
                        true,
                    ),
                ))
            } else {
                Ok((code, format!(
                    "conclusion: {conclusion}\nevidence: {}\nscope: contained synthetic product behavior only\n",
                    out.display()
                )))
            }
        }
        "workflow-verify" => {
            if options.policy.is_some() || options.out.is_some() || options.execute_fixture_workflow
            {
                return Err(CommandError::usage(
                    "workflow-verify requires exactly --bundle DIRECTORY",
                ));
            }
            let bundle = options
                .bundle
                .ok_or_else(|| CommandError::usage("--bundle is required"))?;
            let verified = verify(&bundle).map_err(CommandError::from)?;
            let code = match verified.conclusion {
                WorkflowConclusion::Confirmed => 0,
                WorkflowConclusion::NoEffect => 1,
                WorkflowConclusion::InterpretationFailed
                | WorkflowConclusion::EnvironmentManualReview => 2,
            };
            let conclusion = verified.conclusion.slug();
            let complete = verified.assessment.is_some();
            if options.json {
                Ok((
                    code,
                    display(
                        serde_json::json!({
                            "bundle_version": verified.bundle_version,
                            "conclusion": conclusion,
                            "complete": complete,
                            "assessment": verified.assessment,
                            "diagnostic": verified.diagnostic,
                            "verification": "offline typed-evidence verification only; no driver, target state, network, or process execution",
                        }),
                        true,
                    ),
                ))
            } else {
                Ok((code, format!(
                    "conclusion: {conclusion}\ncomplete: {complete}\nverification: offline evidence consistency only\n"
                )))
            }
        }
        _ => Err(CommandError::usage("unknown workflow command")),
    }
}

fn display(value: serde_json::Value, pretty: bool) -> String {
    let serialized = if pretty {
        serde_json::to_string_pretty(&value)
    } else {
        serde_json::to_string(&value)
    };
    serialized.unwrap_or_else(|_| "{}".into()) + "\n"
}
