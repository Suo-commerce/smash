use serde_json::Value;
use smash_engine::workflow::{verify, WorkflowConclusion};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Fixture {
    root: PathBuf,
    targets: [PathBuf; 3],
}
impl Fixture {
    fn new(label: &str) -> Self {
        let root = PathBuf::from(format!(
            "/tmp/opencode/smash-m5-cli-{label}-{}",
            std::process::id()
        ));
        assert!(!root.exists());
        fs::create_dir(&root).unwrap();
        let source = root.join("revoked_invite.py");
        fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../smash-capstone/fixtures/revoked_invite.py"
            ),
            &source,
        )
        .unwrap();
        let policy_path = root.join("policy.json");
        let mut policy: Value = serde_json::from_slice(
            &fs::read(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../smash-capstone/fixtures/revoked_invite-policy.json"
            ))
            .unwrap(),
        )
        .unwrap();
        policy["run_id"] = Value::String(format!("m5-cli-{label}-{}", std::process::id()));
        policy["broken_driver"]["path"] = Value::from(source.to_string_lossy().as_ref());
        policy["fixed_driver"]["path"] = Value::from(source.to_string_lossy().as_ref());
        let targets = ["broken", "fixed", "control"].map(|kind| {
            PathBuf::from(format!(
                "/tmp/opencode/smash-m5-target-cli-{label}-{kind}-{}",
                std::process::id()
            ))
        });
        for (field, target) in ["broken_root", "fixed_root", "control_root"]
            .iter()
            .zip(&targets)
        {
            policy[*field] = Value::from(target.to_string_lossy().as_ref());
        }
        fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
        Self { root, targets }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for target in &self.targets {
            let _ = fs::remove_dir_all(target);
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn pending(fixture: &Fixture) -> Option<PathBuf> {
    fs::read_dir(&fixture.root)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".workflow.pending-"))
                && path.is_dir()
        })
}

#[test]
fn real_sigint_and_sigterm_cleanup_and_never_publish_interrupted_work() {
    for (label, signal) in [
        ("sigint", rustix::process::Signal::Int),
        ("sigterm", rustix::process::Signal::Term),
    ] {
        let fixture = Fixture::new(label);
        let output_path = fixture.root.join("workflow");
        let mut child = Command::new(env!("CARGO_BIN_EXE_smash"))
            .args([
                "workflow-repro",
                "--policy",
                fixture.root.join("policy.json").to_str().unwrap(),
                "--out",
                output_path.to_str().unwrap(),
                "--execute-fixture-workflow",
                "--json",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let pending = loop {
            if let Some(pending) = pending(&fixture) {
                break pending;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "workflow never reached pending execution: status {:?}; stderr {}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let pid = rustix::process::Pid::from_raw(child.id() as i32).unwrap();
        rustix::process::kill_process(pid, signal).unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "stdout {}; stderr {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !output_path.exists(),
            "{label} published a partial final bundle"
        );
        assert!(!pending.join("manifest.json").exists());
        assert_eq!(
            verify(&pending).unwrap().conclusion,
            WorkflowConclusion::InterpretationFailed
        );
        for target in &fixture.targets {
            assert!(!target.exists(), "{label} left {}", target.display());
        }
        assert!(Path::new(&pending).is_dir());
    }
}
