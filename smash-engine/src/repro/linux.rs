//! Real unprivileged Linux containment. There is deliberately no sandbox fallback.

use crate::repro::error::ReproError;
use sha2::{Digest, Sha256};
use smash_core::execution::{AdmittedExecution, EvidenceState, ExecutionLimits, ReproCheckpoint};
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};
static WORK_SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct PrivateWorkDir {
    path: Option<PathBuf>,
}
impl PrivateWorkDir {
    fn new() -> Result<Self, ReproError> {
        let base = PathBuf::from("/tmp/opencode");
        fs::create_dir_all(&base)?;
        for _ in 0..64 {
            let mut random = [0_u8; 16];
            let count = rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())
                .map_err(|e| ReproError::ExecutionUnavailable(format!("getrandom: {e}")))?;
            if count != random.len() {
                return Err(ReproError::ExecutionUnavailable("short random read".into()));
            }
            let id = format!(
                "smash-m2-{}-{}",
                hex(&random),
                WORK_SEQUENCE.fetch_add(1, Ordering::SeqCst)
            );
            let path = base.join(id);
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                    return Ok(Self { path: Some(path) });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(ReproError::Policy(
            "could not create private work directory".into(),
        ))
    }
    fn path(&self) -> &Path {
        self.path.as_deref().expect("active work directory")
    }
}
impl Drop for PrivateWorkDir {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

pub const LINUX_RUNNER_VERSION: &str = "landlock-seccomp-v1";
const SANDBOX_HELPER: &[u8] = include_bytes!("linux_sandbox.py");
const RETAINED_DIAGNOSTIC_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxArchitecture {
    X86_64,
    Aarch64,
}
impl LinuxArchitecture {
    pub fn host() -> Result<Self, ReproError> {
        match std::env::consts::ARCH {
            "x86_64" => Ok(Self::X86_64),
            "aarch64" => Ok(Self::Aarch64),
            _ => Err(ReproError::ExecutionUnavailable(
                "unsupported Linux architecture".into(),
            )),
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunnerMode {
    Contained,
    UnsafeDevelopment,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxExecutionEnd {
    pub state: EvidenceState,
    pub exit_code: Option<i32>,
    pub successful_exit: Option<bool>,
    pub unresolved: bool,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceObservation {
    pub wall_ms: u64,
    pub cpu_user_us: u64,
    pub cpu_system_us: u64,
    pub max_rss_bytes: Option<u64>,
    pub output_bytes: u64,
    pub memory_limit_bytes: u64,
}

/// M5 retains outcomes rather than arbitrary target stdout/stderr or log text.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessState {
    pub state: String,
    pub termination: String,
    pub exit_code: Option<i32>,
    pub contained: bool,
    pub cleanup_completed: bool,
    pub limits_satisfied: bool,
    pub stderr_excess_bytes: u64,
    pub containment_failures: Vec<String>,
}

#[derive(Debug)]
pub struct LinuxOutput {
    pub end: LinuxExecutionEnd,
    pub resource_output: u64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub declared_outputs: BTreeMap<PathBuf, Vec<u8>>,
    pub cleanup_completed: bool,
    pub contained: bool,
}

impl ProcessState {
    pub fn observed(
        output: &LinuxOutput,
        limits: &ExecutionLimits,
        resource: Option<&ResourceObservation>,
    ) -> Self {
        use smash_core::execution::EvidenceState;
        let mut containment_failures = Vec::new();
        if !output.contained {
            containment_failures.push("not_contained".into());
        }
        if !output.cleanup_completed || output.end.unresolved {
            containment_failures.push("cleanup_or_children_unresolved".into());
        }
        if output.end.state == EvidenceState::EnvironmentSetupFailed {
            containment_failures.push("containment_setup_failed".into());
        }
        let termination = match output.end.state {
            EvidenceState::Succeeded | EvidenceState::ReproductionFailed => "exit",
            EvidenceState::TimedOut => "timeout",
            EvidenceState::Cancelled => "cancelled",
            EvidenceState::OutputLimitExceeded => "output_limit",
            EvidenceState::EnvironmentSetupFailed => "environment_setup",
            EvidenceState::MalformedEvidence => "malformed_output",
            _ => "unresolved",
        };
        Self {
            state: match output.end.state {
                EvidenceState::Succeeded | EvidenceState::ReproductionFailed => "exited",
                EvidenceState::TimedOut => "timed_out",
                EvidenceState::Cancelled => "cancelled",
                EvidenceState::OutputLimitExceeded => "output_limit_exceeded",
                EvidenceState::EnvironmentSetupFailed => "environment_setup_failed",
                EvidenceState::MalformedEvidence => "malformed_evidence",
                _ => "unresolved",
            }
            .into(),
            termination: termination.into(),
            exit_code: output.end.exit_code,
            contained: output.contained,
            cleanup_completed: output.cleanup_completed && !output.end.unresolved,
            limits_satisfied: output.resource_output <= limits.output_bytes
                && resource.is_some_and(|resource| {
                    resource.wall_ms <= limits.wall_ms
                        && resource.memory_limit_bytes == limits.memory_bytes
                        && resource.output_bytes <= limits.output_bytes
                        && resource
                            .max_rss_bytes
                            .is_some_and(|rss| rss <= limits.memory_bytes)
                }),
            stderr_excess_bytes: output.stderr.len() as u64,
            containment_failures,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxJob {
    pub argv: Vec<PathBuf>,
    pub read_roots: Vec<PathBuf>,
    pub read_files: Vec<PathBuf>,
    /// Empty for M2. M5 adds only policy-admitted disposable target roots.
    pub write_roots: Vec<PathBuf>,
    pub output_root: PathBuf,
    pub environment: BTreeMap<String, String>,
    pub limits: ExecutionLimits,
}
impl LinuxJob {
    pub fn scripted(
        fixture: &Path,
        control: &Path,
        output_root: &Path,
        limits: ExecutionLimits,
    ) -> Self {
        Self {
            argv: vec![
                PathBuf::from("/usr/bin/python3"),
                PathBuf::from("-I"),
                PathBuf::from("-B"),
                PathBuf::from("-S"),
                fixture.to_path_buf(),
                PathBuf::from("--control"),
                control.to_path_buf(),
            ],
            read_roots: vec![
                PathBuf::from("/usr"),
                PathBuf::from("/lib"),
                PathBuf::from("/lib64"),
            ],
            read_files: vec![fixture.to_path_buf(), control.to_path_buf()],
            write_roots: Vec::new(),
            output_root: output_root.to_path_buf(),
            environment: BTreeMap::new(),
            limits,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LinuxRunner {
    mode: RunnerMode,
    arch: LinuxArchitecture,
    #[cfg(test)]
    test_cleanup_failure: bool,
    #[cfg(test)]
    test_target_replacement: Option<PathBuf>,
    #[cfg(test)]
    test_before_spawn: Option<(
        std::sync::Arc<std::sync::Barrier>,
        std::sync::Arc<std::sync::Barrier>,
    )>,
}
impl LinuxRunner {
    pub fn contained() -> Result<Self, ReproError> {
        if !cfg!(target_os = "linux") || nix_uid_root() {
            return Err(ReproError::ExecutionUnavailable(
                "unprivileged Linux is required".into(),
            ));
        }
        if !Path::new("/usr/bin/python3").is_file() {
            return Err(ReproError::ExecutionUnavailable(
                "/usr/bin/python3 not found".into(),
            ));
        }
        Ok(Self {
            mode: RunnerMode::Contained,
            arch: LinuxArchitecture::host()?,
            #[cfg(test)]
            test_cleanup_failure: false,
            #[cfg(test)]
            test_target_replacement: None,
            #[cfg(test)]
            test_before_spawn: None,
        })
    }
    /// Explicitly distinct fixture-only development mode; never a containment fallback.
    pub fn unsafe_development(fixture_opt_in: bool) -> Result<Self, ReproError> {
        if !fixture_opt_in {
            return Err(ReproError::ExecutionUnavailable(
                "unsafe fixture opt-in absent".into(),
            ));
        }
        Ok(Self {
            mode: RunnerMode::UnsafeDevelopment,
            arch: LinuxArchitecture::host()?,
            #[cfg(test)]
            test_cleanup_failure: false,
            #[cfg(test)]
            test_target_replacement: None,
            #[cfg(test)]
            test_before_spawn: None,
        })
    }
    pub fn version(&self) -> String {
        format!(
            "{LINUX_RUNNER_VERSION}:{}:{}",
            self.arch.as_str(),
            runner_digest()
        )
    }
    pub fn contained_mode(&self) -> bool {
        self.mode == RunnerMode::Contained
    }

    /// Offline evidence validation checks the retained helper identity without
    /// instantiating a runner, opening the original driver, or probing the host.
    pub fn valid_evidence_version(version: &str) -> bool {
        let Some(architecture) = version
            .strip_prefix(LINUX_RUNNER_VERSION)
            .and_then(|rest| rest.strip_prefix(':'))
            .and_then(|rest| rest.strip_suffix(&format!(":{}", runner_digest())))
        else {
            return false;
        };
        matches!(architecture, "x86_64" | "aarch64")
    }

    /// M5-only authority: exact job, monotonic sequence, immediate start, then consume.
    pub(crate) fn execute_workflow(
        self,
        admitted: crate::workflow::policy::AdmittedWorkflowStep,
        declared_outputs: &[PathBuf],
        cancel: &AtomicBool,
    ) -> Result<(LinuxOutput, crate::workflow::policy::StepBinding), ReproError> {
        if self.mode != RunnerMode::Contained {
            return Err(ReproError::Policy(
                "M5 workflow authority only enters the contained Linux runner".into(),
            ));
        }
        let job = admitted.job().clone();
        let start_ms = self.now_ms();
        let driver_bytes = admitted.driver_bytes.clone();
        let target_root = admitted.pinned_target_root()?;
        let binding = admitted.consume(&job, declared_outputs)?;
        let execution_id = job
            .environment
            .get("SMASH_ATTEMPT_ID")
            .cloned()
            .unwrap_or_else(|| format!("{}:execution", binding.run_namespace));
        let output = self.run_admitted(
            &job,
            execution_id,
            start_ms,
            declared_outputs,
            cancel,
            &mut |_| {},
            Some(WorkflowSnapshot {
                driver_bytes: &driver_bytes,
                target_root: &target_root,
            }),
        )?;
        Ok((output, binding))
    }

    /// The consumed one-shot token cannot be cloned, forged, or reissued from persistence.
    pub fn execute(
        self,
        job: &LinuxJob,
        execution: AdmittedExecution,
        declared_outputs: &[PathBuf],
        cancel: &AtomicBool,
    ) -> Result<LinuxOutput, ReproError> {
        self.execute_observed(job, execution, declared_outputs, cancel, &mut |_| {})
    }
    pub fn execute_observed(
        self,
        job: &LinuxJob,
        execution: AdmittedExecution,
        declared_outputs: &[PathBuf],
        cancel: &AtomicBool,
        observer: &mut dyn FnMut(ReproCheckpoint),
    ) -> Result<LinuxOutput, ReproError> {
        let request = execution.request().clone();
        if job.limits != request.limits {
            return Err(ReproError::Policy(
                "job limits differ from admitted limits".into(),
            ));
        }
        let execution_id = job
            .environment
            .get("SMASH_ATTEMPT_ID")
            .cloned()
            .unwrap_or_else(|| format!("{}:execution", request.run_id));
        let started_at_ms = self.now_ms();
        let checkpoint =
            |sequence: u64, state, output_bytes: u64, terminal: bool| ReproCheckpoint {
                execution_id: execution_id.clone(),
                sequence,
                output_bytes,
                state,
                started_at_ms,
                terminal,
            };
        let _token = execution.consume(started_at_ms)?;
        observer(checkpoint(0, EvidenceState::Admitted, 0, false));
        self.run_admitted(
            job,
            execution_id,
            started_at_ms,
            declared_outputs,
            cancel,
            observer,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn run_admitted(
        self,
        job: &LinuxJob,
        execution_id: String,
        started_at_ms: u64,
        declared_outputs: &[PathBuf],
        cancel: &AtomicBool,
        observer: &mut dyn FnMut(ReproCheckpoint),
        workflow: Option<WorkflowSnapshot<'_>>,
    ) -> Result<LinuxOutput, ReproError> {
        let checkpoint =
            |sequence: u64, state, output_bytes: u64, terminal: bool| ReproCheckpoint {
                execution_id: execution_id.clone(),
                sequence,
                output_bytes,
                state,
                started_at_ms,
                terminal,
            };
        let work = PrivateWorkDir::new()?;
        let root = work.path().join("output");
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let mut execution_job = job.clone();
        if let Some(workflow) = workflow {
            workflow.target_root.verify_current()?;
            stage_workflow_driver(
                work.path(),
                &mut execution_job,
                workflow.driver_bytes,
                self.arch,
            )?;
        } else if mode_is_workflow(job) {
            return Err(ReproError::Policy(
                "M5 requires an immutable driver snapshot".into(),
            ));
        }
        validate_paths(&execution_job, self.mode, &root)?;
        let inherited_target = workflow
            .map(|workflow| workflow.target_root.descriptor().try_clone())
            .transpose()?;
        let configuration = prepare_configuration(
            self.mode,
            &execution_job,
            &root,
            work.path(),
            self.arch,
            inherited_target.as_ref(),
        )?;
        #[cfg(test)]
        if workflow.is_some() {
            if let Some(replacement) = &self.test_target_replacement {
                let target = &job.write_roots[0];
                let pinned = target.with_file_name(format!(
                    "{}-pinned",
                    target.file_name().unwrap().to_string_lossy()
                ));
                fs::rename(target, &pinned)?;
                std::os::unix::fs::symlink(replacement, target)?;
            }
        }
        let helper = write_helper(work.path())?;
        let mut command_line = vec![
            PathBuf::from("-I"),
            PathBuf::from("-B"),
            PathBuf::from("-S"),
            helper,
            configuration,
        ];
        command_line.extend(execution_job.argv.iter().skip(4).cloned());
        // Typed argv only: no shell, model text, or target-controlled environment.
        let mut command = Command::new(&execution_job.argv[0]);
        command.args(command_line);
        command
            .current_dir(&root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        for (key, _) in std::env::vars_os() {
            command.env_remove(key);
        }
        command
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("TMPDIR", &root)
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("PYTHONNOUSERSITE", "1")
            .env("PYTHONHASHSEED", "0");
        for (key, value) in &execution_job.environment {
            command.env(key, value);
        }

        let attempts_started = Instant::now();
        if let Some(target) = &inherited_target {
            inherit_target_in_child(&mut command, target);
        }
        #[cfg(test)]
        if let Some((entered, resume)) = &self.test_before_spawn {
            entered.wait();
            resume.wait();
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let cleanup = cleanup(work);
                return cleanup.and(Err(ReproError::Spawn(error.to_string())));
            }
        };
        observer(checkpoint(1, EvidenceState::Spawned, 0, false));
        let mut collected = collect(&mut child, &job.limits, &attempts_started, cancel);
        observer(checkpoint(
            2,
            EvidenceState::Running,
            collected.resource_output,
            false,
        ));
        let killed = matches!(
            collected.end.state,
            EvidenceState::TimedOut | EvidenceState::Cancelled
        ) || collected.end.unresolved
            || collected.resource_output > job.limits.output_bytes;
        if collected.resource_output > job.limits.output_bytes {
            collected.end.state = EvidenceState::OutputLimitExceeded;
        }
        if killed && !terminate_group(&mut child) {
            collected.end.unresolved = true;
        }
        let mut stdout = collected.stdout;
        let mut stderr = collected.stderr;
        // Delayed EOFs cannot prolong a completed attempt indefinitely.
        if !collected.end.unresolved {
            match child.wait() {
                Ok(status) if !killed => {
                    collected.end.state = if status.success() {
                        EvidenceState::Succeeded
                    } else {
                        EvidenceState::ReproductionFailed
                    };
                    collected.end.exit_code = status.code();
                    collected.end.successful_exit = Some(status.success());
                }
                Ok(status) => collected.end.exit_code = status.code(),
                Err(_) => collected.end.unresolved = true,
            }
        }
        terminate_group(&mut child);
        let target_identity_valid = workflow.map_or(true, |workflow| {
            workflow.target_root.verify_current().is_ok()
        });
        let declared_outputs = if !target_identity_valid {
            BTreeMap::new()
        } else {
            match collect_outputs(&root, declared_outputs, job.limits.output_bytes) {
                Ok(outputs) => outputs,
                Err(error)
                    if matches!(
                        collected.end.state,
                        EvidenceState::Succeeded | EvidenceState::ReproductionFailed
                    ) =>
                {
                    collected.end.state = EvidenceState::MalformedEvidence;
                    collected.end.successful_exit = None;
                    stderr.extend_from_slice(error.to_string().as_bytes());
                    BTreeMap::new()
                }
                Err(_) => BTreeMap::new(),
            }
        };
        if !target_identity_valid {
            collected.end.state = EvidenceState::MalformedEvidence;
            collected.end.exit_code = None;
            collected.end.successful_exit = None;
            stderr.extend_from_slice(b"workflow target identity changed during execution");
        }
        #[cfg(not(test))]
        let cleanup_completed = cleanup(work).is_ok();
        #[cfg(test)]
        let cleanup_completed = if self.test_cleanup_failure {
            let _ = cleanup(work);
            false
        } else {
            cleanup(work).is_ok()
        };
        if setup_failed(&stderr) {
            collected.end.state = EvidenceState::EnvironmentSetupFailed;
            collected.end.exit_code = None;
            collected.end.successful_exit = None;
            collected.end.unresolved = false;
        }
        if !cleanup_completed {
            collected.end.unresolved = true;
            collected.end.successful_exit = None;
        }
        stdout.truncate(RETAINED_DIAGNOSTIC_BYTES);
        stderr.truncate(RETAINED_DIAGNOSTIC_BYTES);
        Ok(LinuxOutput {
            end: collected.end,
            resource_output: collected.resource_output,
            stdout,
            stderr,
            declared_outputs,
            cleanup_completed,
            contained: self.mode == RunnerMode::Contained,
        })
    }
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

#[derive(Clone, Copy)]
struct WorkflowSnapshot<'a> {
    driver_bytes: &'a [u8],
    target_root: &'a crate::workflow::policy::PinnedTargetRoot,
}

struct Collected {
    end: LinuxExecutionEnd,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    resource_output: u64,
}
fn collect(
    child: &mut Child,
    limits: &ExecutionLimits,
    started: &Instant,
    cancel: &AtomicBool,
) -> Collected {
    let out = channel_for(child.stdout.take());
    let err = channel_for(child.stderr.take());
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut closed = [false; 2];
    let mut child_done = false;
    let deadline = *started + Duration::from_millis(limits.wall_ms);
    let mut end = LinuxExecutionEnd {
        state: EvidenceState::Spawned,
        exit_code: None,
        successful_exit: None,
        unresolved: false,
    };
    end.state = EvidenceState::Running;
    while !(closed[0] && closed[1] && child_done) {
        drain(&out, &mut stdout, &mut closed[0]);
        drain(&err, &mut stderr, &mut closed[1]);
        let total = (stdout.len() + stderr.len()) as u64;
        if total > limits.output_bytes {
            return Collected {
                end: LinuxExecutionEnd {
                    state: EvidenceState::ReproductionFailed,
                    exit_code: None,
                    successful_exit: None,
                    unresolved: false,
                },
                stdout,
                stderr,
                resource_output: total,
            };
        }
        if Instant::now() >= deadline {
            return Collected {
                end: LinuxExecutionEnd {
                    state: EvidenceState::TimedOut,
                    exit_code: None,
                    successful_exit: None,
                    unresolved: false,
                },
                stdout,
                stderr,
                resource_output: total,
            };
        }
        if cancel.load(Ordering::SeqCst) {
            return Collected {
                end: LinuxExecutionEnd {
                    state: EvidenceState::Cancelled,
                    exit_code: None,
                    successful_exit: None,
                    unresolved: false,
                },
                stdout,
                stderr,
                resource_output: total,
            };
        }
        if matches!(child.try_wait(), Ok(Some(_))) {
            child_done = true;
            drain(&out, &mut stdout, &mut closed[0]);
            drain(&err, &mut stderr, &mut closed[1]);
        }
        thread::sleep(Duration::from_millis(2));
    }
    let total = (stdout.len() + stderr.len()) as u64;
    Collected {
        end,
        stdout,
        stderr,
        resource_output: total,
    }
}
fn channel_for<R: Read + Send + 'static>(reader: Option<R>) -> Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::channel();
    if let Some(mut reader) = reader {
        thread::spawn(move || {
            let mut buffer = [0; 8192];
            while let Ok(count) = reader.read(&mut buffer) {
                if count == 0 || sender.send(buffer[..count].to_vec()).is_err() {
                    break;
                }
            }
        });
    }
    receiver
}
fn drain(receiver: &Receiver<Vec<u8>>, output: &mut Vec<u8>, closed: &mut bool) {
    loop {
        match receiver.try_recv() {
            Ok(bytes) => output.extend(bytes),
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => {
                *closed = true;
                break;
            }
        }
    }
}
fn terminate_group(child: &mut Child) -> bool {
    if let Some(pgid) = rustix::process::Pid::from_raw(child.id() as i32) {
        let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::Kill);
    }
    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    false
}
fn nix_uid_root() -> bool {
    rustix::process::getuid().is_root()
}

fn prepare_configuration(
    mode: RunnerMode,
    job: &LinuxJob,
    output: &Path,
    work: &Path,
    arch: LinuxArchitecture,
    workflow_target: Option<&File>,
) -> Result<PathBuf, ReproError> {
    let mut config = BTreeMap::new();
    config.insert("arch", serde_json::Value::from(arch.as_str()));
    config.insert(
        "output_root",
        serde_json::Value::from(output.to_string_lossy().as_ref()),
    );
    config.insert(
        "contained",
        serde_json::Value::from(mode == RunnerMode::Contained),
    );
    config.insert("path", serde_json::Value::from("/usr/bin:/bin"));
    config.insert(
        "single_driver",
        serde_json::Value::from(mode_is_workflow(job)),
    );
    config.insert("environment", serde_json::to_value(&job.environment)?);
    let memory = if mode == RunnerMode::Contained {
        job.limits.memory_bytes
    } else {
        job.limits.memory_bytes * 2
    };
    config.insert(
        "limits",
        serde_json::json!({"cpu_s": job.limits.wall_ms.div_ceil(1000).max(1),
        "memory_bytes": memory, "output_bytes": job.limits.output_bytes,
        "processes": job.limits.processes}),
    );
    config.insert("read_roots", paths_json(&job.read_roots)?);
    if mode_is_workflow(job) {
        let target = workflow_target.ok_or_else(|| {
            ReproError::Policy("M5 requires a pinned workflow target directory".into())
        })?;
        config.insert(
            "write_roots",
            serde_json::Value::Array(vec![serde_json::Value::from(format!(
                "/proc/self/fd/{}",
                target.as_raw_fd()
            ))]),
        );
    } else {
        config.insert("write_roots", paths_json(&job.write_roots)?);
    }
    let mut files = job.read_files.clone();
    files.sort();
    files.dedup();
    config.insert("read_files", paths_json(&files)?);
    let argv: Vec<_> = job
        .argv
        .iter()
        .map(|part| part.as_os_str().to_string_lossy().to_string())
        .collect();
    config.insert("argv", serde_json::to_value(argv)?);
    let path = work.join("scope.json");
    write_private(&path, &serde_json::to_vec(&config)?)?;
    Ok(path)
}
fn write_helper(work: &Path) -> Result<PathBuf, ReproError> {
    let path = work.join("sandbox.py");
    write_private(&path, SANDBOX_HELPER)?;
    Ok(path)
}

fn mode_is_workflow(job: &LinuxJob) -> bool {
    !job.write_roots.is_empty()
}

#[allow(unsafe_code)]
fn inherit_target_in_child(command: &mut Command, target: &File) {
    let raw_fd = target.as_raw_fd();
    // SAFETY: `target` remains alive in the parent until `spawn` returns. The
    // child closure runs before exec and only borrows that live descriptor for
    // one async-signal-safe fcntl. No allocation, locking, or foreign process
    // descriptor flags are touched; the parent's descriptor stays CLOEXEC.
    unsafe {
        command.pre_exec(move || {
            let target = BorrowedFd::borrow_raw(raw_fd);
            rustix::io::fcntl_setfd(target, rustix::io::FdFlags::empty())
                .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))
        });
    }
}

/// M5 starts one Python process. Its first exec is the trusted helper bootstrap;
/// the launcher installs a second filter before executing the exact reviewed bytes,
/// so neither that driver nor its descendants can fork, clone, or exec again.
fn stage_workflow_driver(
    work: &Path,
    job: &mut LinuxJob,
    bytes: &[u8],
    arch: LinuxArchitecture,
) -> Result<(), ReproError> {
    if bytes.is_empty() || bytes.len() > 65_536 || job.write_roots.len() != 1 || job.argv.len() < 5
    {
        return Err(ReproError::Policy(
            "invalid M5 immutable driver request".into(),
        ));
    }
    let source_path = work.join("reviewed_driver.py");
    let launcher_path = work.join("workflow_launcher.py");
    job.read_files.retain(|file| *file != job.argv[4]);
    job.argv[4] = launcher_path.clone();
    job.read_files
        .extend([launcher_path.clone(), source_path.clone()]);
    write_private(&source_path, bytes)?;
    let marker = b"\nif __name__ == \"__main__\":";
    let definitions = SANDBOX_HELPER
        .windows(marker.len())
        .position(|window| window == marker)
        .map(|end| &SANDBOX_HELPER[..end])
        .ok_or_else(|| ReproError::Evidence("trusted sandbox entry point is missing".into()))?;
    let mut launcher = definitions.to_vec();
    let arch_string = arch.as_str();
    write!(
        launcher,
        "\n__source_path = {source_path:?}\n\
         __fd = os.open(__source_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)\n\
         __source = os.read(__fd, 65537)\n\
         os.close(__fd)\n\
         if not __source or len(__source) > 65536: fail('immutable driver bound')\n\
         __libc = ctypes.CDLL(None, use_errno=True)\n\
         __libc.syscall.restype = ctypes.c_long\n\
         # The first trusted bootstrap validated this same process architecture.\n\
         seccomp(__libc, {{'arch': {arch_string:?}, 'single_driver': True}}, True, False)\n\
         exec(compile(__source, __source_path, 'exec'), \
             {{'__name__': '__main__', '__file__': __source_path}})\n",
    )
    .map_err(|_| ReproError::Evidence("could not generate trusted workflow launcher".into()))?;
    write_private(&launcher_path, &launcher)?;
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ReproError> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}
fn validate_paths(
    job: &LinuxJob,
    mode: RunnerMode,
    actual_output: &Path,
) -> Result<(), ReproError> {
    if job.argv.is_empty()
        || job.argv[0] != Path::new("/usr/bin/python3")
        || job.argv.get(1).map(PathBuf::as_path) != Some(Path::new("-I"))
        || job.argv.get(2).map(PathBuf::as_path) != Some(Path::new("-B"))
        || job.argv.get(3).map(PathBuf::as_path) != Some(Path::new("-S"))
        || job
            .environment
            .keys()
            .any(|key| key.contains('=') || key.contains('\0'))
        || job.environment.values().any(|value| value.contains('\0'))
    {
        return Err(ReproError::Policy(
            "scripted runner arguments are fixed".into(),
        ));
    }
    // M2's caller-selected staging path remains validated exactly as before.
    // M5 binds a symbolic result filename and the runner owns the actual staging root.
    if job.write_roots.is_empty() {
        canonical(&job.output_root)?;
    } else if job.output_root != Path::new("result.json") {
        return Err(ReproError::Policy("invalid M5 symbolic result path".into()));
    }
    let output = canonical(actual_output)?;
    if !valid_private_root(output.as_ref())
        || job.read_roots.iter().any(|r| output.starts_with(r))
        || (mode == RunnerMode::Contained && job.read_files.iter().any(|p| !p.is_file()))
    {
        return Err(ReproError::Policy(
            "invalid source/output containment paths".into(),
        ));
    }
    if mode == RunnerMode::Contained {
        for path in &job.read_roots {
            if !canonical(path)?.is_dir() {
                return Err(ReproError::Policy("bad read root".into()));
            }
        }
        for path in &job.write_roots {
            let root = canonical(path)?;
            if !root.is_dir()
                || root != *path
                || root == output
                || root.starts_with(&output)
                || output.starts_with(&root)
                || job.read_roots.iter().any(|read| root.starts_with(read))
            {
                return Err(ReproError::Policy("bad writable target root".into()));
            }
        }
        for path in &job.read_files {
            let canonical = canonical(path)?;
            // Each regular file is its own explicit read capability; it need not
            // also be under a directory capability.
            if !canonical.is_file() {
                return Err(ReproError::Policy("read file is not regular".into()));
            }
        }
    }
    Ok(())
}
fn canonical(path: &Path) -> Result<PathBuf, ReproError> {
    fs::canonicalize(path)
        .map_err(|error| ReproError::Policy(format!("canonicalize {}: {error}", path.display())))
}
fn valid_private_root(root: &Path) -> bool {
    root.is_dir()
        && !root.iter().any(|part| part == "..")
        && root
            .components()
            .all(|part| !matches!(part, Component::CurDir | Component::ParentDir))
}
fn paths_json(paths: &[PathBuf]) -> Result<serde_json::Value, ReproError> {
    if paths.iter().any(|p| !p.is_absolute()) {
        return Err(ReproError::Policy("relative sandbox path".into()));
    }
    Ok(serde_json::to_value(
        paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect::<Vec<_>>(),
    )?)
}
fn collect_outputs(
    root: &Path,
    declared: &[PathBuf],
    max: u64,
) -> Result<BTreeMap<PathBuf, Vec<u8>>, ReproError> {
    let mut result = BTreeMap::new();
    let mut remaining = max;
    for relative in declared {
        let path = root.join(relative);
        let bytes = crate::workflow::policy::bounded_source_read(&path, remaining)
            .map_err(|error| ReproError::Evidence(error.to_string()))?;
        remaining = remaining.saturating_sub(bytes.len() as u64);
        result.insert(relative.clone(), bytes);
    }
    Ok(result)
}
fn setup_failed(stderr: &[u8]) -> bool {
    stderr.starts_with(b"M2_SETUP_FAILED:")
}
fn cleanup(work: PrivateWorkDir) -> Result<(), ReproError> {
    let path = work.path().to_path_buf();
    fs::remove_dir_all(path).map_err(|error| ReproError::Cleanup(error.to_string()))
}
fn runner_digest() -> String {
    hex(&Sha256::digest(SANDBOX_HELPER))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workflow_step(
        label: &str,
    ) -> (
        crate::workflow::WorkflowPolicy,
        crate::workflow::policy::AdmittedWorkflowStep,
        PathBuf,
        PrivateWorkDir,
    ) {
        use crate::repro::policy::BoundedLimits;
        use crate::workflow::policy::{WorkflowDriver, WorkflowIdentities};
        use crate::workflow::{
            REVOKED_INVITE_DRIVER_SHA256, REVOKED_INVITE_ORACLE, REVOKED_INVITE_SCENARIO,
            SYNTHETIC_GUEST_CREDENTIAL_REFERENCE, WorkflowPolicy, WorkflowRunKind,
        };

        let work = PrivateWorkDir::new().unwrap();
        let driver = work.path().join("revoked_invite.py");
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../smash-capstone/fixtures/revoked_invite.py"),
            &driver,
        )
        .unwrap();
        let root = PathBuf::from(format!(
            "/tmp/opencode/smash-m5-target-linux-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let reviewed = WorkflowDriver {
            path: driver.clone(),
            sha256: REVOKED_INVITE_DRIVER_SHA256.into(),
        };
        let policy = WorkflowPolicy {
            protocol_version: 1,
            run_id: format!("m5-linux-{label}"),
            scenario: REVOKED_INVITE_SCENARIO.into(),
            oracle: REVOKED_INVITE_ORACLE.into(),
            provider: "linux-landlock-seccomp".into(),
            evidence_schema: 1,
            broken_driver: reviewed.clone(),
            fixed_driver: reviewed,
            broken_root: root.clone(),
            fixed_root: root.with_file_name(format!(
                "{}-fixed",
                root.file_name().unwrap().to_string_lossy()
            )),
            control_root: root.with_file_name(format!(
                "{}-control",
                root.file_name().unwrap().to_string_lossy()
            )),
            identities: WorkflowIdentities {
                project: "project".into(),
                owner: "owner".into(),
                guest: "guest".into(),
                invitation: "invitation".into(),
            },
            credential_reference: SYNTHETIC_GUEST_CREDENTIAL_REFERENCE.into(),
            limits: BoundedLimits {
                wall_ms: 5_000,
                output_bytes: 65_536,
                memory_bytes: 128 * 1_048_576,
                processes: 1,
            },
            synthetic_guests: true,
            disposable_targets: true,
            target_destruction: true,
            network: "none".into(),
            unsafe_development: false,
        };
        let target_root =
            crate::workflow::policy::checked_target_root(&policy.broken_root).unwrap();
        let mut admission = policy.review(true).unwrap();
        let mut run = admission
            .begin_run(&policy, WorkflowRunKind::Broken, &target_root)
            .unwrap();
        let step = run.admit_step(Path::new("result.json")).unwrap();
        (policy, step, driver, work)
    }

    fn single_driver_probe(label: &str, source: &[u8]) -> LinuxOutput {
        let (policy, mut step, _driver, _work) = workflow_step(label);
        // This test-only substitution happens after policy review so the kernel
        // boundary, rather than source admission, is what is being exercised.
        step.driver_bytes = source.to_vec();
        let output = LinuxRunner::contained()
            .unwrap()
            .execute_workflow(
                step,
                &[PathBuf::from("result.json")],
                &AtomicBool::new(false),
            )
            .unwrap()
            .0;
        fs::remove_dir_all(&policy.broken_root).unwrap();
        output
    }

    #[test]
    fn m5_executes_reviewed_bytes_after_the_original_driver_is_replaced() {
        let (policy, step, driver, _work) = workflow_step("snapshot");
        fs::write(
            &driver,
            b"raise RuntimeError('replacement must never execute')\n",
        )
        .unwrap();
        let output = LinuxRunner::contained()
            .unwrap()
            .execute_workflow(
                step,
                &[PathBuf::from("result.json")],
                &AtomicBool::new(false),
            )
            .unwrap()
            .0;
        assert_eq!(
            output.end.state,
            EvidenceState::Succeeded,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: serde_json::Value =
            serde_json::from_slice(&output.declared_outputs[Path::new("result.json")]).unwrap();
        assert_eq!(result["state"]["project"], "project");
        assert_eq!(result["state"]["sequence"], 1);
        fs::remove_dir_all(&policy.broken_root).unwrap();
    }

    #[test]
    fn m5_single_driver_profile_denies_children_reexec_and_network() {
        let probes: [(&str, &[u8]); 4] = [
            ("child", b"import os\nos.fork()\n"),
            (
                "shell",
                b"import os\nos.execv('/bin/sh', ['sh', '-c', 'id'])\n",
            ),
            (
                "reexec",
                b"import os\nos.execv('/usr/bin/python3', ['python3', __file__])\n",
            ),
            ("network", b"import socket\nsocket.socket()\n"),
        ];
        for (label, source) in probes {
            let output = single_driver_probe(label, source);
            assert!(
                !output.end.successful_exit.unwrap_or(false),
                "{label} escaped"
            );
            assert!(
                output.declared_outputs.is_empty(),
                "{label} emitted trusted evidence"
            );
            assert!(
                output.contained && output.cleanup_completed,
                "{label} left unresolved execution"
            );
        }
    }

    #[test]
    fn m5_declared_output_symlink_is_malformed_not_read() {
        let output = single_driver_probe(
            "output-symlink",
            b"import os\nos.symlink('/definitely/not/a/source', 'result.json')\n",
        );
        assert_eq!(output.end.state, EvidenceState::MalformedEvidence);
        assert!(output.declared_outputs.is_empty());
    }

    #[test]
    fn m5_replaced_target_cannot_redirect_containment_grants_or_evidence() {
        let (policy, step, _driver, _work) = workflow_step("target-replacement");
        let replacement = policy.broken_root.with_file_name(format!(
            "{}-replacement",
            policy.broken_root.file_name().unwrap().to_string_lossy()
        ));
        let _ = fs::remove_dir_all(&replacement);
        fs::create_dir(&replacement).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
        let mut runner = LinuxRunner::contained().unwrap();
        runner.test_target_replacement = Some(replacement.clone());
        let output = runner
            .execute_workflow(
                step,
                &[PathBuf::from("result.json")],
                &AtomicBool::new(false),
            )
            .unwrap()
            .0;
        assert_eq!(output.end.state, EvidenceState::MalformedEvidence);
        assert!(output.declared_outputs.is_empty());
        assert!(!replacement.join("state.json").exists());
        fs::remove_file(&policy.broken_root).unwrap();
        let pinned = policy.broken_root.with_file_name(format!(
            "{}-pinned",
            policy.broken_root.file_name().unwrap().to_string_lossy()
        ));
        fs::remove_dir_all(pinned).unwrap();
        fs::remove_dir_all(replacement).unwrap();
    }

    #[test]
    fn m5_target_capability_never_leaks_into_a_concurrent_m2_spawn() {
        use std::sync::{Arc, Barrier};

        let (policy, mut step, _driver, _work) = workflow_step("descriptor");
        step.driver_bytes = b"open('result.json', 'w').write('{}')\n".to_vec();
        let entered = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        let mut runner = LinuxRunner::contained().unwrap();
        runner.test_before_spawn = Some((Arc::clone(&entered), Arc::clone(&resume)));
        let workflow = thread::spawn(move || {
            runner
                .execute_workflow(
                    step,
                    &[PathBuf::from("result.json")],
                    &AtomicBool::new(false),
                )
                .unwrap()
        });
        // In the old parent-side CLOEXEC toggle, this M2 spawn deterministically
        // inherited the paused M5 descriptor. Child-local fcntl transfer leaves
        // both the parent and all unrelated children without that root.
        entered.wait();
        let unrelated = execute_fixture("foreign_fd", 65_536, 5_000);
        resume.wait();
        let (workflow_output, _) = workflow.join().unwrap();
        assert_eq!(workflow_output.end.state, EvidenceState::Succeeded);
        assert_eq!(
            unrelated.declared_outputs[Path::new("result.json")],
            b"not-leaked"
        );
        fs::remove_dir_all(&policy.broken_root).unwrap();
    }

    #[test]
    fn all_runner_paths_require_absolute_arguments_and_bounded_outputs() {
        let root = PathBuf::from("/tmp/output");
        let job = LinuxJob::scripted(
            Path::new("/fixture"),
            Path::new("/control"),
            &root,
            ExecutionLimits::bounded(),
        );
        assert_eq!(job.argv[1], Path::new("-I"));
    }
    #[test]
    fn relative_paths_and_root_are_refused() {
        let job = LinuxJob::scripted(
            Path::new("relative"),
            Path::new("/control"),
            Path::new("out"),
            ExecutionLimits::bounded(),
        );
        assert!(validate_paths(&job, RunnerMode::Contained, Path::new("/tmp/output")).is_err());
    }
    #[test]
    fn helper_is_identity_bound() {
        assert_eq!(runner_digest().len(), 64);
    }

    fn execute_fixture(probe: &str, output_limit: u64, wall_ms: u64) -> LinuxOutput {
        let cancel = AtomicBool::new(false);
        execute_fixture_with(probe, output_limit, wall_ms, 128 * 1_048_576, 8, &cancel)
    }
    fn execute_fixture_with(
        probe: &str,
        output_limit: u64,
        wall_ms: u64,
        memory: u64,
        processes: u32,
        cancel: &AtomicBool,
    ) -> LinuxOutput {
        execute_fixture_injected(
            probe,
            output_limit,
            wall_ms,
            memory,
            processes,
            cancel,
            |_| {},
        )
    }
    fn execute_fixture_injected(
        probe: &str,
        output_limit: u64,
        wall_ms: u64,
        memory: u64,
        processes: u32,
        cancel: &AtomicBool,
        inject: impl FnOnce(&mut LinuxRunner),
    ) -> LinuxOutput {
        use smash_core::execution::*;
        let work = PrivateWorkDir::new().unwrap();
        let fixture = work.path().join("fixture.py");
        fs::write(&fixture, r#"import os, socket, time
probe = os.environ.get("SMASH_PROBE", "normal")
if probe == "network":
    socket.socket()
elif probe == "cancel":
    time.sleep(30)
elif probe == "memory":
    data = bytearray(256 * 1024 * 1024)
elif probe == "file":
    open("result.json", "wb").write(b"x" * 10000)
elif probe == "descendant":
    import subprocess
    try:
        child = subprocess.Popen(["/usr/bin/python3", "-I", "-B", "-S", "-c",
            "import os,time;os.setsid();time.sleep(60)"])
        time.sleep(0.05)
        open("result.json", "w").write("no-escape" if child.poll() is not None else "alive")
    except BlockingIOError:
        open("result.json", "w").write("process-limit")
elif probe == "source_write":
    try:
        open(os.path.realpath(__file__), "a")
        open("result.json", "w").write("writable")
    except PermissionError:
        open("result.json", "w").write("read-only")
elif probe == "timeout":
    time.sleep(30)
elif probe == "output":
    os.write(1, b"x" * 10000)
elif probe == "foreign_fd":
    leaked = False
    for descriptor in os.listdir("/proc/self/fd"):
        try:
            path = os.path.realpath("/proc/self/fd/" + descriptor)
            if os.path.basename(path).startswith("smash-m5-target-linux-descriptor-"):
                leaked = True
        except OSError:
            pass
    open("result.json", "w").write("leaked" if leaked else "not-leaked")
else:
    open("result.json", "w").write("minimal-environment" if os.environ.get("HOME") is None else "inherited")
"#).unwrap();
        fs::set_permissions(&fixture, fs::Permissions::from_mode(0o555)).unwrap();
        let output = work.path().join("staged-output");
        fs::create_dir(&output).unwrap();
        let draft = ExperimentDraft {
            authority: RepositoryAuthority::new(
                RepositoryDepth::LocalGitProject,
                CheckoutPermission::ReadWrite,
                true,
                1,
                1,
            ),
            protocol_version: 1,
            operation: ReproOperation::RegressionPair,
            attack_class: "smoke".into(),
            target_tool: "fixture".into(),
            research_fingerprint_prefix: "0123456789abcdef".into(),
        };
        let admitted = ExecutionAdmission.admit(&draft).unwrap();
        let limits = ExecutionLimits {
            wall_ms,
            output_bytes: output_limit,
            memory_bytes: memory,
            processes,
        };
        let request = ExecutionRequest {
            run_id: "smoke".into(),
            target_identity: TargetIdentity {
                repository_fingerprint: "fixture".into(),
                contract_sha256: "33".repeat(32),
                entrypoint_sha256: "11".repeat(32),
                runtime: "python3".into(),
                platform: "linux".into(),
            },
            artifact: ControlArtifact {
                path: PathBuf::from("fixture.py"),
                sha256: "22".repeat(32),
                declared_outputs: vec![],
            },
            limits: limits.clone(),
        };
        let runner = RunnerAvailability {
            supported: true,
            identity_matches: true,
            initialization_dry_run_passed: true,
            missing_tools: vec![],
        };
        let execution = AdmittedExecution::bind_execution(
            &admitted,
            request,
            EphemeralCleanup,
            &runner,
            SystemExecutionClock.now_ms(),
        )
        .unwrap();
        let mut job = LinuxJob::scripted(&fixture, &fixture, &output, limits);
        if probe == "foreign_fd" {
            job.read_roots.push(PathBuf::from("/proc/self/fd"));
        }
        job.environment.insert("SMASH_PROBE".into(), probe.into());
        let mut runner = LinuxRunner::contained().unwrap();
        inject(&mut runner);
        runner
            .execute(&job, execution, &[PathBuf::from("result.json")], cancel)
            .unwrap()
    }
    #[test]
    fn actual_provider_retains_cleanup_failure_as_unresolved_non_green() {
        let cancel = AtomicBool::new(false);
        let output = execute_fixture_injected(
            "normal",
            65536,
            5000,
            128 * 1_048_576,
            8,
            &cancel,
            |runner| runner.test_cleanup_failure = true,
        );
        assert!(!output.cleanup_completed && output.end.unresolved);
        assert_ne!(output.end.successful_exit, Some(true));
    }
    #[test]
    fn actual_provider_isolates_filesystem_and_environment() {
        let output = execute_fixture("normal", 65536, 5000);
        assert_eq!(
            output.end.state,
            EvidenceState::Succeeded,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.contained && output.cleanup_completed);
        assert_eq!(
            output.declared_outputs[Path::new("result.json")],
            b"minimal-environment"
        );
        let source = execute_fixture("source_write", 65536, 5000);
        assert_eq!(
            source.declared_outputs[Path::new("result.json")],
            b"read-only"
        );
    }
    #[test]
    fn actual_provider_denies_network_and_bounds_runaways() {
        let network = execute_fixture("network", 65536, 5000);
        assert!(matches!(
            network.end.state,
            EvidenceState::ReproductionFailed | EvidenceState::MalformedEvidence
        ));
        assert!(!network.end.successful_exit.unwrap_or(false));
        let timeout = execute_fixture("timeout", 65536, 100);
        assert_eq!(timeout.end.state, EvidenceState::TimedOut);
        let output = execute_fixture("output", 64, 5000);
        assert_eq!(output.end.state, EvidenceState::OutputLimitExceeded);
        assert!(!output.end.successful_exit.unwrap_or(false));
    }
    #[test]
    fn actual_provider_enforces_cancellation_memory_file_and_descendant_limits() {
        use std::sync::Arc;
        let cancel = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&cancel);
        let canceller = thread::spawn(move || {
            thread::sleep(Duration::from_millis(75));
            signal.store(true, Ordering::SeqCst);
        });
        let cancelled = execute_fixture_with("cancel", 65536, 5000, 128 * 1_048_576, 8, &cancel);
        canceller.join().unwrap();
        assert_eq!(cancelled.end.state, EvidenceState::Cancelled);
        assert!(cancelled.cleanup_completed);
        let memory = execute_fixture("memory", 65536, 5000);
        assert_ne!(memory.end.state, EvidenceState::Succeeded);
        assert!(memory.cleanup_completed);
        let file = execute_fixture("file", 64, 5000);
        assert_ne!(file.end.state, EvidenceState::Succeeded);
        assert!(file.cleanup_completed);
        let child = execute_fixture("descendant", 65536, 5000);
        assert_eq!(
            child.end.state,
            EvidenceState::Succeeded,
            "{}",
            String::from_utf8_lossy(&child.stderr)
        );
        assert!(matches!(
            child.declared_outputs[Path::new("result.json")].as_slice(),
            b"no-escape" | b"process-limit"
        ));
    }
}
