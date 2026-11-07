use crate::{load_script, read_bounded, Options};
use smash_agent::investigation::ScriptedInvestigationPlanner;
use smash_engine::canonical::parse_no_duplicates;
use smash_engine::http::bundle::{persist_bundle, persist_discovery, verify_bundle};
use smash_engine::http::campaign::{
    discover, execute_campaign, HttpCampaignPolicy, HttpOutcome, MAX_PLAN_BYTES,
};
use smash_engine::http::investigation::policy::{
    HttpInvestigationPolicy, MAX_INVESTIGATION_POLICY_BYTES,
};
use smash_engine::http::investigation::session::{
    resume_investigation, start_investigation, verification_report, verify_session,
    InvestigationRunStatus,
};
use smash_engine::recon::load_verified_campaign;
use std::path::Path;

pub(super) fn command(name: &str, options: Options) -> Result<(i32, String), String> {
    if matches!(
        name,
        "http-investigate" | "http-investigate-resume" | "http-investigate-verify"
    ) {
        return investigation_command(name, options);
    }
    if !options.unnamed.is_empty()
        || options.target.is_some()
        || options.repo.is_some()
        || options.script.is_some()
        || options.max_experiments.is_some()
        || options.max_queries.is_some()
    {
        return Err("HTTP commands accept only --policy, --out/--bundle, --run-id, and --json; http-repro additionally requires --execute-fixture-mutations".into());
    }
    match name {
        "http-verify" => {
            if options.policy.is_some()
                || options.out.is_some()
                || options.run_id.is_some()
                || options.execute_fixture_mutations
            {
                return Err("http-verify requires exactly --bundle DIRECTORY [--json]".into());
            }
            let root = required(options.bundle, "--bundle")?;
            let bundle = verify_bundle(&root).map_err(|error| error.to_string())?;
            Ok((
                i32::from(!bundle.assessment.reproduced),
                display(
                    serde_json::json!({
                        "schema_version":1,
                        "valid":true,
                        "reproduced":bundle.assessment.reproduced,
                        "verdict":bundle.assessment.verdict,
                        "scope":"offline consistency of admitted scalar evidence; no authenticity, security, or exploitability claim",
                        "network":"not used",
                    }),
                    options.json,
                ),
            ))
        }
        "http-discover" | "http-repro" => {
            if options.bundle.is_some() {
                return Err(format!("{name} requires --policy FILE --out DIRECTORY"));
            }
            let path = required(options.policy, "--policy")?;
            let out = required(options.out, "--out")?;
            let mut policy = load_policy(&path)?;
            if let Some(run_id) = options.run_id {
                policy.run_id = run_id;
            }
            policy.validate().map_err(|error| error.to_string())?;
            if name == "http-discover" {
                if options.execute_fixture_mutations {
                    return Err("http-discover does not accept mutation execution".into());
                }
                let evidence = discover(&policy, &mut environment_credential)
                    .map_err(|error| error.to_string())?;
                persist_discovery(&out, &evidence).map_err(|error| error.to_string())?;
                let complete = evidence
                    .calls
                    .iter()
                    .all(|call| call.outcome == HttpOutcome::Observed);
                let report = serde_json::json!({
                    "schema_version":1,
                    "control":evidence.control,
                    "discovered":false,
                    "completed":complete,
                    "coverage":{
                        "planned":evidence.calls.len(),
                        "observed":evidence.calls.iter().filter(|call| call.outcome == HttpOutcome::Observed).count(),
                        "unsupported":"unlisted routes, schemas, redirect targets, dynamic planning, and general security properties"
                    },
                    "evidence":evidence,
                    "scope":"read-only scalar route observations; no dynamic vulnerability verdict"
                });
                return Ok((if complete { 0 } else { 2 }, display(report, options.json)));
            }
            if !options.execute_fixture_mutations {
                return Err("http-repro requires explicit --execute-fixture-mutations and an admitted effect contract".into());
            }
            if policy.effect.is_none() {
                return Err(
                    "http-repro requires one declared mutation and correlated state observations"
                        .into(),
                );
            }
            // The generic CLI has no authority to claim teardown for an external
            // provider. In a real run this preserves valid but inconclusive records
            // rather than fabricating clean containment. Target-specific providers
            // supply the actual fixture cleanup callback, as the M3 capstone does.
            let (broken, fixed, assessment) =
                execute_campaign(&policy, environment_credential, |_| false)
                    .map_err(|error| error.to_string())?;
            let bundle = persist_bundle(&out, policy, broken, fixed, assessment)
                .map_err(|error| error.to_string())?;
            let report = serde_json::json!({
                "schema_version":1,
                "reproduced":bundle.assessment.reproduced,
                "verdict":bundle.assessment.verdict,
                "fixture_cleanup_attested":false,
                "scope":"external fixture providers must attest teardown before a differential can be reproduced; no general security claim"
            });
            Ok((
                i32::from(!bundle.assessment.reproduced),
                display(report, options.json),
            ))
        }
        _ => Err("unknown HTTP subcommand".into()),
    }
}

fn investigation_command(name: &str, options: Options) -> Result<(i32, String), String> {
    if !options.unnamed.is_empty()
        || options.target.is_some()
        || options.repo.is_some()
        || options.max_experiments.is_some()
        || options.max_queries.is_some()
        || options.execute_fixture_mutations
    {
        return Err("M4 investigation commands accept only --policy, --out/--bundle, --script, --run-id, --recon-bundle, and --json".into());
    }
    if name == "http-investigate-verify" {
        if options.policy.is_some()
            || options.out.is_some()
            || options.script.is_some()
            || options.run_id.is_some()
        {
            return Err(
                "http-investigate-verify requires exactly --bundle DIRECTORY [--json]".into(),
            );
        }
        let root = required(options.bundle, "--bundle")?;
        let verified = verify_session(&root).map_err(|error| error.to_string())?;
        let report = verification_report(&verified);
        return Ok((
            0,
            display(
                serde_json::to_value(report).map_err(|error| error.to_string())?,
                options.json,
            ),
        ));
    }

    if options.bundle.is_some() {
        return Err(format!(
            "{name} requires --policy FILE --script FILE --out DIRECTORY"
        ));
    }
    let path = required(options.policy, "--policy")?;
    let script = required(options.script, "--script")?;
    let out = required(options.out, "--out")?;
    let mut policy = load_investigation_policy(&path)?;
    if let Some(run_id) = options.run_id {
        policy.campaign.run_id = run_id;
    }
    if policy.recon_seed.is_some() {
        return Err(
            "recon_seed is generated by the CLI; supply recon links and --recon-bundle instead"
                .into(),
        );
    }
    match (options.recon_bundle.as_ref(), policy.recon.is_some()) {
        (Some(bundle), true) => {
            let verified = load_verified_campaign(bundle).map_err(|error| {
                format!("recon seed verification failed before investigation: {error}")
            })?;
            policy
                .attach_verified_recon(&verified)
                .map_err(|error| error.to_string())?;
        }
        (None, true) => {
            return Err(
                "a recon-seeded investigation and its resume require --recon-bundle".into(),
            );
        }
        (Some(_), false) => {
            return Err("--recon-bundle requires recon links in the M4 policy".into());
        }
        (None, false) => {}
    }
    policy.validate().map_err(|error| error.to_string())?;
    let responses = load_script(&script)?;
    if responses.len() > policy.budgets.max_planner_turns as usize {
        return Err("investigation script exceeds the planner-turn budget".into());
    }
    let mut planner = ScriptedInvestigationPlanner::new(responses);
    planner
        .validate_script()
        .map_err(|error| error.to_string())?;
    let report = if name == "http-investigate" {
        start_investigation(&out, &policy, &mut planner, environment_credential)
    } else {
        resume_investigation(&out, &policy, &mut planner, environment_credential)
    }
    .map_err(|error| error.to_string())?;
    let successful = matches!(
        report.status,
        InvestigationRunStatus::Complete | InvestigationRunStatus::AlreadyComplete
    ) && report.all_items_complete;
    Ok((
        if successful { 0 } else { 2 },
        display(
            serde_json::to_value(report).map_err(|error| error.to_string())?,
            options.json,
        ),
    ))
}

fn load_investigation_policy(path: &Path) -> Result<HttpInvestigationPolicy, String> {
    let bytes = read_bounded(path, MAX_INVESTIGATION_POLICY_BYTES)?;
    let value = parse_no_duplicates(&bytes).map_err(|error| error.to_string())?;
    serde_json::from_value(value)
        .map_err(|error| format!("invalid M4 HTTP investigation policy: {error}"))
}

fn required(value: Option<std::path::PathBuf>, name: &str) -> Result<std::path::PathBuf, String> {
    value.ok_or_else(|| format!("{name} is required"))
}

fn load_policy(path: &Path) -> Result<HttpCampaignPolicy, String> {
    let bytes = read_bounded(path, MAX_PLAN_BYTES)?;
    let value = parse_no_duplicates(&bytes).map_err(|error| error.to_string())?;
    serde_json::from_value(value).map_err(|error| format!("invalid HTTP campaign policy: {error}"))
}

fn environment_credential(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn display(value: serde_json::Value, json: bool) -> String {
    if json {
        format!(
            "{}\n",
            serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".into())
        )
    } else {
        let label = match value.get("verdict").and_then(serde_json::Value::as_str) {
            Some(verdict) => verdict,
            None if value.get("completed").and_then(serde_json::Value::as_bool) == Some(true) => {
                "read-only observation complete"
            }
            None => "incomplete or denied observation",
        };
        format!(
            "{label}\n{}\n",
            serde_json::to_string_pretty(&value).unwrap_or_default()
        )
    }
}
