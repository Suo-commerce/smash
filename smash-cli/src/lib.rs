//! Separate, explicitly bounded M1/M2, static M3 HTTP, and M4 investigation commands.

use serde::Deserialize;
use serde_json::Value;
use smash_agent::ScriptedPlanner;
use smash_core::research::{RunPolicy, TargetKind, TargetManifest, RESEARCH_SCHEMA_VERSION};
use smash_engine::canonical::{canonical_json, parse_no_duplicates};
use smash_engine::recon::{
    verify_campaign, write_campaign, CampaignRunner, CampaignStatus, ProviderRecord,
    ReadOnlyRepository,
};
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
mod http;
mod repro;
mod workflow;

const USAGE: &str = "Usage:\n  smash recon --target MANIFEST.json --script PLAN.json --out DIRECTORY [--run-id ID] [--max-experiments N] [--max-queries N]\n  smash recon --repo DIRECTORY --script PLAN.json --out DIRECTORY [--run-id ID]\n  smash verify --bundle DIRECTORY [--json]\n  smash repro --policy POLICY.json --out DIRECTORY [--run-id ID] [--json]\n  smash repro-verify --bundle DIRECTORY [--json]\n  smash repro-resume --policy POLICY.json --bundle DIRECTORY [--json]\n  smash repro-rerun --policy POLICY.json --out DIRECTORY [--json]\n  smash workflow-repro --policy POLICY.json --out DIRECTORY --execute-fixture-workflow [--json]\n  smash workflow-verify --bundle DIRECTORY [--json]\n  smash http-discover --policy POLICY.json --out DIRECTORY [--run-id ID] [--json]\n  smash http-repro --policy POLICY.json --out DIRECTORY --execute-fixture-mutations [--json]\n  smash http-verify --bundle DIRECTORY [--json]\n  smash http-investigate --policy POLICY.json --script PLAN.json --out DIRECTORY [--run-id ID] [--recon-bundle DIRECTORY] [--json]\n  smash http-investigate-resume --policy POLICY.json --script PLAN.json --out DIRECTORY [--recon-bundle DIRECTORY] [--json]\n  smash http-investigate-verify --bundle DIRECTORY [--json]\n\nRepository reconnaissance is read-only. Reports contain source observations and hypotheses, not dynamically verified vulnerabilities.\nReproduction is opt-in and limited to the typed authenticated-retry Linux fixture. Reproduced means a scoped policy violation, not security or exploitability.\nHTTP discovery admits read-only scalar routes only. HTTP reproduction requires explicit mutation opt-in, declared loopback fixture origins, and correlated effect observations; external fixture cleanup is never presumed.\nM4 investigation allows only scripted selection from a pre-admitted read-only HTTP catalog. An optional verified recon bundle supplies bounded source provenance only, never HTTP authority. It provides no arbitrary authority, general vulnerability detection, or target-authenticity claim.\n";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetFile {
    schema_version: u32,
    target_id: String,
    kind: String,
    locator: String,
    description: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptFile {
    schema_version: u32,
    responses: Vec<Value>,
}

pub fn run(
    arguments: impl Iterator<Item = OsString>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let arguments: Vec<String> = match arguments.map(|argument| argument.into_string()).collect() {
        Ok(arguments) => arguments,
        Err(_) => {
            let _ = writeln!(stderr, "arguments must be valid UTF-8");
            return 2;
        }
    };
    let Some(command) = arguments.first() else {
        let _ = write!(stderr, "{USAGE}");
        return 2;
    };
    let options = match Options::parse(&arguments[1..]) {
        Ok(options) => options,
        Err(error) => {
            let _ = writeln!(stderr, "{error}\n{USAGE}");
            return 2;
        }
    };
    if options.execute_fixture_workflow && command != "workflow-repro" {
        let _ = writeln!(
            stderr,
            "--execute-fixture-workflow is exclusive to workflow-repro"
        );
        return 2;
    }
    if options.recon_bundle.is_some()
        && !matches!(
            command.as_str(),
            "http-investigate" | "http-investigate-resume"
        )
    {
        let _ = writeln!(
            stderr,
            "--recon-bundle is exclusive to http-investigate and http-investigate-resume"
        );
        return 2;
    }
    match command.as_str() {
        "http-discover"
        | "http-repro"
        | "http-verify"
        | "http-investigate"
        | "http-investigate-resume"
        | "http-investigate-verify" => match http::command(command.as_str(), options) {
            Ok((code, output)) => {
                let _ = write!(stdout, "{output}");
                code
            }
            Err(error) => {
                let _ = writeln!(stderr, "{command} failed: {error}");
                2
            }
        },
        "repro" | "repro-verify" | "repro-resume" | "repro-rerun" => {
            match repro::command(command, options) {
                Ok((code, output)) => {
                    let _ = write!(stdout, "{output}");
                    code
                }
                Err(error) => {
                    let _ = writeln!(stderr, "{command} failed: {error}");
                    2
                }
            }
        }
        "workflow-repro" | "workflow-verify" => match workflow::command(command, options) {
            Ok((code, output)) => {
                let _ = write!(stdout, "{output}");
                code
            }
            Err(error) => {
                let _ = writeln!(stderr, "{command} failed: {}", error.message);
                error.code
            }
        },
        "recon" => match recon(options) {
            Ok((status, output)) => {
                let _ = writeln!(stdout, "campaign: {}", output.display());
                let _ = writeln!(stdout, "status: {status:?}");
                let _ = writeln!(
                    stdout,
                    "evidence: source observations only; no dynamic vulnerability verification"
                );
                if status == CampaignStatus::Completed {
                    0
                } else {
                    2
                }
            }
            Err(error) => {
                let _ = writeln!(stderr, "recon failed: {error}");
                2
            }
        },
        "verify" => match options.bundle {
            Some(bundle) if options.unnamed.is_empty() && !options.execute_fixture_mutations => {
                let report = verify_campaign(&bundle);
                if options.json {
                    let value = serde_json::json!({
                        "schema_version": 1,
                        "valid": report.is_valid(),
                        "checks": report.checks,
                        "failures": report.failures,
                    });
                    let _ = writeln!(
                        stdout,
                        "{}",
                        serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_owned())
                    );
                } else {
                    for check in &report.checks {
                        let _ = writeln!(stdout, "ok: {check}");
                    }
                    for failure in &report.failures {
                        let _ = writeln!(stdout, "FAIL: {failure}");
                    }
                    let _ = writeln!(stdout, "valid: {}", report.is_valid());
                }
                i32::from(!report.is_valid())
            }
            _ => {
                let _ = writeln!(
                    stderr,
                    "verify requires exactly --bundle DIRECTORY\n{USAGE}"
                );
                2
            }
        },
        "help" | "--help" | "-h" => {
            let _ = write!(stdout, "{USAGE}");
            0
        }
        _ => {
            let _ = writeln!(stderr, "unknown command {command}\n{USAGE}");
            2
        }
    }
}

fn recon(options: Options) -> Result<(CampaignStatus, PathBuf), String> {
    if !options.unnamed.is_empty()
        || options.bundle.is_some()
        || options.policy.is_some()
        || options.execute_fixture_mutations
    {
        return Err("recon does not accept positional, --bundle, --policy, or HTTP mutation execution arguments".to_owned());
    }
    let target = match (options.target, options.repo) {
        (Some(manifest), None) => load_target(&manifest)?,
        (None, Some(repository)) => {
            TargetManifest::repository("repository", path_text(&repository)?)
                .map_err(|error| error.to_string())?
        }
        _ => return Err("choose exactly one of --target or --repo".to_owned()),
    };
    let script = options
        .script
        .ok_or_else(|| "--script is required".to_owned())?;
    let output = options.out.ok_or_else(|| "--out is required".to_owned())?;
    let run_id = options.run_id.unwrap_or_else(|| "recon-run".to_owned());
    let mut policy = RunPolicy::repository_read_only();
    if let Some(limit) = options.max_experiments {
        policy.max_experiments = positive(limit, "max-experiments")?;
        policy.max_completed_experiments = policy.max_experiments;
    }
    if let Some(limit) = options.max_queries {
        policy.max_queries = positive(limit, "max-queries")?;
    }
    policy.validate().map_err(|error| error.to_string())?;
    let responses = load_script(&script)?;
    if responses.len() > policy.max_queries as usize {
        return Err("script has more responses than the query policy permits".to_owned());
    }
    let mut planner = ScriptedPlanner::new(responses);
    planner
        .validate_script()
        .map_err(|error| error.to_string())?;
    let mut repository = ReadOnlyRepository::open(&target)?;
    let campaign = CampaignRunner::new(
        run_id,
        target,
        policy,
        ProviderRecord::scripted("recon-script/v1"),
    )?
    .run(&mut planner, &mut repository);
    let status = campaign.status;
    write_campaign(&output, &campaign)?;
    Ok((status, output))
}

fn load_target(path: &Path) -> Result<TargetManifest, String> {
    let bytes = read_bounded(path, 1024 * 1024)?;
    let value = parse_no_duplicates(&bytes).map_err(|error| error.to_string())?;
    let manifest: TargetFile = serde_json::from_value(value)
        .map_err(|error| format!("invalid target manifest: {error}"))?;
    if manifest.schema_version != RESEARCH_SCHEMA_VERSION || manifest.kind != "repository" {
        return Err("manifest must declare schema_version 1 and kind repository".to_owned());
    }
    let target = TargetManifest {
        schema_version: manifest.schema_version,
        target_id: manifest.target_id,
        kind: TargetKind::Repository,
        locator: manifest.locator,
        description: manifest.description,
    };
    target.validate().map_err(|error| error.to_string())?;
    Ok(target)
}

fn load_script(path: &Path) -> Result<Vec<Vec<u8>>, String> {
    let bytes = read_bounded(path, 16 * 1024 * 1024)?;
    let value = parse_no_duplicates(&bytes).map_err(|error| format!("invalid script: {error}"))?;
    let script: ScriptFile =
        serde_json::from_value(value).map_err(|error| format!("invalid script: {error}"))?;
    if script.schema_version != RESEARCH_SCHEMA_VERSION || script.responses.is_empty() {
        return Err(
            "script must use schema_version 1 and contain at least one response".to_owned(),
        );
    }
    script
        .responses
        .into_iter()
        .map(|response| Ok(canonical_json(&response).into_bytes()))
        .collect::<Result<Vec<_>, String>>()
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(format!(
            "{} must be a bounded regular non-symlink file",
            path.display()
        ));
    }
    let file = std::fs::File::open(path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() as u64 > limit {
        return Err(format!("{} exceeds its size limit", path.display()));
    }
    Ok(bytes)
}

fn positive(value: u32, name: &str) -> Result<u32, String> {
    if value == 0 {
        Err(format!("{name} must be positive"))
    } else {
        Ok(value)
    }
}

fn path_text(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| "paths must be valid UTF-8".to_owned())
}

#[derive(Default)]
struct Options {
    target: Option<PathBuf>,
    repo: Option<PathBuf>,
    script: Option<PathBuf>,
    policy: Option<PathBuf>,
    out: Option<PathBuf>,
    bundle: Option<PathBuf>,
    recon_bundle: Option<PathBuf>,
    run_id: Option<String>,
    max_experiments: Option<u32>,
    max_queries: Option<u32>,
    execute_fixture_mutations: bool,
    execute_fixture_workflow: bool,
    json: bool,
    unnamed: Vec<String>,
}

impl Options {
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let mut options = Self::default();
        let mut index = 0;
        while index < arguments.len() {
            let name = arguments[index].as_str();
            if name == "--json" {
                options.json = true;
                index += 1;
                continue;
            }
            if name == "--execute-fixture-mutations" {
                if options.execute_fixture_mutations {
                    return Err("--execute-fixture-mutations supplied more than once".into());
                }
                options.execute_fixture_mutations = true;
                index += 1;
                continue;
            }
            if name == "--execute-fixture-workflow" {
                if options.execute_fixture_workflow {
                    return Err("--execute-fixture-workflow supplied more than once".into());
                }
                options.execute_fixture_workflow = true;
                index += 1;
                continue;
            }
            if name.starts_with('-') {
                let value = arguments
                    .get(index + 1)
                    .ok_or_else(|| format!("{name} requires a value"))?;
                match name {
                    "--target" => set_once(&mut options.target, PathBuf::from(value), name)?,
                    "--repo" => set_once(&mut options.repo, PathBuf::from(value), name)?,
                    "--script" => set_once(&mut options.script, PathBuf::from(value), name)?,
                    "--policy" => set_once(&mut options.policy, PathBuf::from(value), name)?,
                    "--out" => set_once(&mut options.out, PathBuf::from(value), name)?,
                    "--bundle" => set_once(&mut options.bundle, PathBuf::from(value), name)?,
                    "--recon-bundle" => {
                        set_once(&mut options.recon_bundle, PathBuf::from(value), name)?
                    }
                    "--run-id" => set_once(&mut options.run_id, value.clone(), name)?,
                    "--max-experiments" => {
                        options.max_experiments = Some(
                            value
                                .parse()
                                .map_err(|_| "--max-experiments must be an integer".to_owned())?,
                        )
                    }
                    "--max-queries" => {
                        options.max_queries = Some(
                            value
                                .parse()
                                .map_err(|_| "--max-queries must be an integer".to_owned())?,
                        )
                    }
                    _ => return Err(format!("unknown option {name}")),
                }
                index += 2;
            } else {
                options.unnamed.push(value_or_name(name));
                index += 1;
            }
        }
        Ok(options)
    }
}

fn value_or_name(name: &str) -> String {
    name.to_owned()
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        Err(format!("{name} supplied more than once"))
    } else {
        Ok(())
    }
}
