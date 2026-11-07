use crate::{read_bounded, Options};
use smash_core::execution::{
    CheckoutPermission, ExecutionAdmission, ExperimentDraft, RepositoryAuthority, RepositoryDepth,
    ReproAdmission, ReproCheckpoint, ReproOperation,
};
use smash_engine::repro::bundle::{
    persist_bundle_with_journal, persist_denial, resume_bundle, verify_bundle, JournalLine,
    ReproductionBundle, ResumeDecision,
};
use smash_engine::repro::policy::{
    admit_artifact, policy_digest, run_scripted_regression_observed, trusted_fixture_digest,
    ReproductionArtifact, ReproductionPolicy, ReproductionRun, AUTHENTICATED_REPRO_TOOL,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

pub(super) fn command(name: &str, options: Options) -> Result<(i32, String), String> {
    if !options.unnamed.is_empty()
        || options.target.is_some()
        || options.repo.is_some()
        || options.script.is_some()
        || options.max_experiments.is_some()
        || options.max_queries.is_some()
        || options.execute_fixture_mutations
    {
        return Err(
            "repro commands accept only --policy, --out/--bundle, --run-id, and --json".into(),
        );
    }
    match name {
        "repro-verify" => {
            if options.policy.is_some() || options.run_id.is_some() || options.out.is_some() {
                return Err("repro-verify requires exactly --bundle DIRECTORY".into());
            }
            let bundle = options
                .bundle
                .ok_or_else(|| "--bundle is required".to_owned())?;
            let verified = verify_bundle(&bundle).map_err(|error| error.to_string())?;
            let report = serde_json::json!({
                "schema_version": 1, "valid": true, "reproduced": verified.reproduced,
                "resume": format!("{:?}", verified.resume),
                "scope": "dynamic scoped policy violation only; no security or exploitability claim",
                "verification": "offline evidence consistency only; not fresh runtime reproduction",
            });
            Ok((
                i32::from(!verified.reproduced),
                display(&report, options.json),
            ))
        }
        "repro" | "repro-rerun" => {
            if options.bundle.is_some() {
                return Err(format!("{name} requires --policy FILE --out DIRECTORY"));
            }
            let path = options
                .policy
                .ok_or_else(|| "--policy is required".to_owned())?;
            let out = options.out.ok_or_else(|| "--out is required".to_owned())?;
            let mut policy = load_policy(&path)?;
            if let Some(run_id) = options.run_id {
                if run_id.trim().is_empty() {
                    return Err("--run-id must not be empty".into());
                }
                policy.run_id = run_id;
            }
            if name == "repro-rerun" {
                policy.run_id = format!(
                    "{}:fresh-{}",
                    policy.run_id,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis()
                );
            }
            // Validate and copy the typed artifact before obtaining execution authority.
            let artifact = match admit_artifact(&policy, &policy.artifact) {
                Ok(artifact) => artifact,
                Err(error) => {
                    let record =
                        persist_denial(&out, &policy, &error).map_err(|error| error.to_string())?;
                    let report = serde_json::json!({"schema_version":1, "reproduced":false,
                        "denial":format!("{:?}", record.denial),
                        "scope":"unadmitted artifact; no execution authority was obtained"});
                    return Ok((2, display(&report, options.json)));
                }
            };
            // A fresh, unserializable authority is linked to only this exact operation.
            let admitted = ExecutionAdmission
                .admit(&ExperimentDraft {
                    authority: RepositoryAuthority::new(
                        RepositoryDepth::LocalGitProject,
                        CheckoutPermission::ReadWrite,
                        true,
                        1,
                        1,
                    ),
                    protocol_version: 1,
                    operation: ReproOperation::RegressionPair,
                    attack_class: "authenticated-state-retry".into(),
                    target_tool: AUTHENTICATED_REPRO_TOOL.into(),
                    research_fingerprint_prefix: "0123456789abcdef".into(),
                })
                .map_err(|error| format!("execution authority denied: {error:?}"))?;
            if out.exists() {
                return Err(
                    "refusing to overwrite an existing result or resume it as fresh".into(),
                );
            }
            let mut journal = LiveJournal::create(&out, &policy)?;
            let run = match run_scripted_regression_observed(
                &policy,
                &admitted,
                &AtomicBool::new(false),
                &mut |checkpoint| journal.observe(checkpoint),
            ) {
                Ok(run) => run,
                Err(error) => {
                    let record =
                        persist_denial(&out, &policy, &error).map_err(|error| error.to_string())?;
                    let report = serde_json::json!({"schema_version":1, "reproduced":false,
                        "denial":format!("{:?}", record.denial),
                        "scope":"denial or missing evidence is never a reproduced vulnerability"});
                    return Ok((2, display(&report, options.json)));
                }
            };
            let bundle = journal.finish(&out, &policy, &artifact, run)?;
            let report = serde_json::json!({
                "schema_version":1, "reproduced":bundle.assessment.reproduced(),
                "contained":bundle.broken.output.contained && bundle.fixed.output.contained,
                "assessment":bundle.assessment,
                "verification":"offline evidence consistency only; verify does not execute or replay",
            });
            Ok((
                i32::from(!bundle.assessment.reproduced()),
                display(&report, options.json),
            ))
        }
        "repro-resume" => {
            if options.out.is_some() || options.run_id.is_some() {
                return Err(
                    "repro-resume requires exactly --policy FILE --bundle DIRECTORY".into(),
                );
            }
            let path = options
                .policy
                .ok_or_else(|| "--policy is required".to_owned())?;
            let root = options
                .bundle
                .ok_or_else(|| "--bundle is required".to_owned())?;
            let policy = load_policy(&path)?;
            let artifact =
                admit_artifact(&policy, &policy.artifact).map_err(|error| error.to_string())?;
            let broken =
                trusted_fixture_digest(&policy.broken_root).map_err(|error| error.to_string())?;
            let fixed =
                trusted_fixture_digest(&policy.fixed_root).map_err(|error| error.to_string())?;
            let decision = resume_bundle(&root, &policy, &artifact.sha256, &broken, &fixed)
                .map_err(|error| error.to_string())?;
            let report = serde_json::json!({
                "schema_version":1, "resume":format!("{:?}",decision),
                "replayed":false,
                "reproduced":verify_bundle(&root).map_err(|error| error.to_string())?.reproduced,
                "scope":"a digest match proves identity and consistency, not authenticity or security",
            });
            let code = if decision == ResumeDecision::CompletedWithoutReplay {
                0
            } else {
                2
            };
            Ok((code, display(&report, options.json)))
        }
        _ => Err("unknown repro subcommand".into()),
    }
}

struct LiveJournal {
    pending: PathBuf,
    file: fs::File,
    failure: Option<String>,
}
impl LiveJournal {
    fn create(destination: &Path, policy: &ReproductionPolicy) -> Result<Self, String> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let pending = pending_path(destination)?;
        fs::create_dir(&pending)
            .map_err(|error| format!("create private journal directory: {error}"))?;
        fs::set_permissions(&pending, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(pending.join("journal.jsonl"))
            .map_err(|error| error.to_string())?;
        let mut journal = Self {
            pending,
            file,
            failure: None,
        };
        journal.append(&JournalLine::Header {
            schema_version: 1,
            run_id: policy.run_id.clone(),
            policy_sha256: policy_digest(policy).map_err(|error| error.to_string())?,
        })?;
        if journal.failure.is_some() {
            return Err("could not sync live journal header".into());
        }
        Ok(journal)
    }
    fn observe(&mut self, checkpoint: ReproCheckpoint) {
        if self.failure.is_none() {
            let result = self.append(&JournalLine::Checkpoint {
                checkpoint: checkpoint.into(),
            });
            if let Err(error) = result {
                self.failure = Some(error);
            }
        }
    }
    fn append(&mut self, line: &JournalLine) -> Result<(), String> {
        use std::io::Write;
        let mut bytes = serde_json::to_vec(line).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        self.file
            .write_all(&bytes)
            .and_then(|()| self.file.sync_data())
            .map_err(|error| format!("append and sync live checkpoint: {error}"))
    }
    fn finish(
        mut self,
        destination: &Path,
        policy: &ReproductionPolicy,
        artifact: &ReproductionArtifact,
        run: ReproductionRun,
    ) -> Result<ReproductionBundle, String> {
        use std::io::Read;
        if let Some(error) = self.failure.take() {
            return Err(error);
        }
        self.file.sync_all().map_err(|error| error.to_string())?;
        let mut bytes = Vec::new();
        fs::File::open(self.pending.join("journal.jsonl"))
            .map_err(|error| error.to_string())?
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() > 1_048_576 {
            return Err("live journal exceeds bound".into());
        }
        let completed = self.pending.join("complete");
        let bundle = persist_bundle_with_journal(&completed, policy, artifact, run, Some(&bytes))
            .map_err(|error| error.to_string())?;
        if destination.exists() {
            return Err("destination appeared during execution; refusing overwrite".into());
        }
        fs::rename(&completed, destination).map_err(|error| error.to_string())?;
        let _ = fs::remove_dir_all(&self.pending);
        Ok(bundle)
    }
}
fn pending_path(destination: &Path) -> Result<PathBuf, String> {
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        return Err("output parent must be an existing directory".into());
    }
    let name = destination
        .file_name()
        .ok_or_else(|| "output directory must have a name".to_owned())?
        .to_string_lossy();
    for sequence in 0..16_u32 {
        let path = parent.join(format!(
            ".smash-m2-{name}-{}-{sequence}",
            std::process::id()
        ));
        if !path.exists() {
            return Ok(path);
        }
    }
    Err("no fresh private journal directory".into())
}

fn load_policy(path: &Path) -> Result<ReproductionPolicy, String> {
    let bytes = read_bounded(path, 1024 * 1024)?;
    let mut policy: ReproductionPolicy = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid reproduction policy: {error}"))?;
    let base = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !policy.broken_root.is_absolute() {
        policy.broken_root = base.join(&policy.broken_root);
    }
    if !policy.fixed_root.is_absolute() {
        policy.fixed_root = base.join(&policy.fixed_root);
    }
    if !policy.artifact.is_absolute() {
        policy.artifact = base.join(&policy.artifact);
    }
    for path in [
        &mut policy.broken_root,
        &mut policy.fixed_root,
        &mut policy.artifact,
    ] {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect input path: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("policy roots and artifacts must not be symlinks".into());
        }
        *path = fs::canonicalize(&path)
            .map_err(|error| format!("cannot canonicalize input path: {error}"))?;
    }
    Ok(policy)
}

fn display(value: &serde_json::Value, json: bool) -> String {
    if json {
        serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".into())
    } else {
        format!(
            "reproduced: {}\n{}\n",
            value
                .get("reproduced")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            serde_json::to_string_pretty(value).unwrap_or_default()
        )
    }
}
