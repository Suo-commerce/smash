//! M2's committed, authorized broken/fixed repository capstone.
//!
//! Only the reviewed authenticated-retry fixture runs. Its source contains example
//! hostile requests that are never compiled, treated as commands, or used as evidence.
//! `Reproduced` is the scoped dynamic policy violation, not a security verdict.

use smash_engine::repro::bundle::{
    resume_bundle, verify_bundle, ReproductionBundle, ResumeDecision,
};
use smash_engine::repro::policy::{
    admit_artifact, trusted_fixture_digest, AUTHENTICATED_REPRO_ENTRYPOINT, M2_FIXTURE_ENTRYPOINT,
};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/repro");

struct Fixture {
    path: PathBuf,
}
impl Fixture {
    fn new(label: &str) -> Self {
        let nonce = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(format!(
            "/tmp/opencode/smash-m2-{label}-{}-{nonce}",
            std::process::id()
        ));
        assert!(!path.exists());
        fs::create_dir_all(&path).unwrap();
        for variant in ["broken", "fixed"] {
            let root = path.join(variant);
            fs::create_dir(&root).unwrap();
            fs::copy(
                format!("{FIXTURES}/{variant}/control.py"),
                root.join("control.py"),
            )
            .unwrap();
            fs::write(
                root.join(AUTHENTICATED_REPRO_ENTRYPOINT),
                M2_FIXTURE_ENTRYPOINT,
            )
            .unwrap();
        }
        for file in ["artifact.json", "policy.json"] {
            fs::copy(format!("{FIXTURES}/{file}"), path.join(file)).unwrap();
        }
        Self { path }
    }
    fn path(&self, file: &str) -> PathBuf {
        self.path.join(file)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn command(_fixture: &Fixture, name: &str, argument: &str, path: &str) -> (i32, serde_json::Value) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = smash_cli::run(
        [
            OsString::from(name),
            OsString::from(argument),
            OsString::from(path),
            OsString::from("--json"),
        ]
        .into_iter(),
        &mut stdout,
        &mut stderr,
    );
    let text = String::from_utf8(stdout).unwrap();
    let value = serde_json::from_str(&text).unwrap_or_else(|error| {
        panic!(
            "{name} returned invalid JSON: {error}; {text}; stderr: {}",
            String::from_utf8(stderr).unwrap()
        )
    });
    (code, value)
}
fn create(fixture: &Fixture, output: &str) -> (i32, serde_json::Value) {
    create_named(fixture, "repro", output)
}
fn create_named(fixture: &Fixture, name: &str, output: &str) -> (i32, serde_json::Value) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = smash_cli::run(
        [
            OsString::from(name),
            OsString::from("--policy"),
            OsString::from(fixture.path("policy.json")),
            OsString::from("--out"),
            OsString::from(output),
            OsString::from("--json"),
        ]
        .into_iter(),
        &mut stdout,
        &mut stderr,
    );
    let text = String::from_utf8(stdout).unwrap();
    let value = serde_json::from_str(&text).unwrap_or_else(|error| {
        panic!(
            "repro returned invalid JSON: {error}; {text}; stderr: {}",
            String::from_utf8(stderr).unwrap()
        )
    });
    (code, value)
}
fn verify(
    path: &Path,
) -> Result<smash_engine::repro::bundle::VerifiedBundle, smash_engine::repro::error::ReproError> {
    verify_bundle(path)
}
#[track_caller]
fn resume(fixture: &Fixture, bundle: &str) -> ((i32, serde_json::Value), String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = smash_cli::run(
        [
            OsString::from("repro-resume"),
            OsString::from("--policy"),
            OsString::from(fixture.path("policy.json")),
            OsString::from("--bundle"),
            OsString::from(bundle),
            OsString::from("--json"),
        ]
        .into_iter(),
        &mut stdout,
        &mut stderr,
    );
    let text = String::from_utf8(stdout).unwrap();
    let error_text = String::from_utf8(stderr).unwrap();
    let value = if text.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or_else(|error| {
            panic!("resume returned invalid JSON: {error}; {text}; stderr: {error_text}")
        })
    };
    ((code, value), error_text)
}

#[test]
fn paired_controls_verify_offline_and_completed_resume_never_replays() {
    let fixture = Fixture::new("positive");
    let output = fixture.path("bundle");
    let path = output.to_str().unwrap();
    let (code, report) = create(&fixture, path);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["reproduced"], true);
    assert_eq!(report["contained"], true);
    let (code, verified) = command(&fixture, "repro-verify", "--bundle", path);
    assert_eq!(code, 0, "{verified}");
    assert_eq!(verified["reproduced"], true);

    let manifest: ReproductionBundle =
        serde_json::from_slice(&fs::read(output.join("manifest.json")).unwrap()).unwrap();
    let policy = manifest.policy.clone();
    assert_ne!(
        manifest.broken.identity.repository_fingerprint,
        manifest.fixed.identity.repository_fingerprint
    );
    assert_eq!(
        manifest.broken.artifact.sha256,
        manifest.fixed.artifact.sha256
    );
    assert!(manifest
        .assessment
        .limitations
        .iter()
        .any(|item| item.contains("does not establish security")));
    let journal = fs::read(output.join("journal.jsonl")).unwrap();
    assert_eq!(journal.iter().filter(|byte| **byte == b'\n').count(), 9);
    let checkpoints: usize = manifest.broken.checkpoints.len() + manifest.fixed.checkpoints.len();
    assert_eq!(checkpoints, 8);

    let original_policy = fs::read(fixture.path("policy.json")).unwrap();
    let mut mismatched_policy: serde_json::Value =
        serde_json::from_slice(&original_policy).unwrap();
    mismatched_policy["run_id"] = serde_json::Value::String("mismatched-run".into());
    fs::write(
        fixture.path("policy.json"),
        serde_json::to_vec(&mismatched_policy).unwrap(),
    )
    .unwrap();
    let ((code, mismatch), _) = resume(&fixture, path);
    assert_eq!(code, 2);
    assert_eq!(mismatch["resume"], "RefuseMismatch");
    assert_eq!(mismatch["replayed"], false);
    assert_eq!(fs::read(output.join("journal.jsonl")).unwrap(), journal);
    fs::write(fixture.path("policy.json"), &original_policy).unwrap();

    let ((code, resumed), _) = resume(&fixture, path);
    assert_eq!(code, 0, "{resumed}");
    assert_eq!(resumed["replayed"], false);
    assert_eq!(resumed["resume"], "CompletedWithoutReplay");
    assert_eq!(fs::read(output.join("journal.jsonl")).unwrap(), journal);

    let fresh = fixture.path("rerun");
    let (code, result) = create_named(&fixture, "repro-rerun", fresh.to_str().unwrap());
    assert_eq!(code, 0, "{result}");
    let rerun: ReproductionBundle =
        serde_json::from_slice(&fs::read(fresh.join("manifest.json")).unwrap()).unwrap();
    assert_ne!(rerun.run_id, manifest.run_id);

    let artifact = admit_artifact(&policy, &policy.artifact).unwrap();
    let broken = trusted_fixture_digest(&policy.broken_root).unwrap();
    let fixed = trusted_fixture_digest(&policy.fixed_root).unwrap();
    let original_manifest = fs::read(output.join("manifest.json")).unwrap();
    let mut tampered: serde_json::Value = serde_json::from_slice(&original_manifest).unwrap();
    tampered["fixed"]["identity"]["contract_sha256"] = serde_json::Value::String("00".repeat(32));
    fs::write(
        output.join("manifest.json"),
        serde_json::to_vec(&tampered).unwrap(),
    )
    .unwrap();
    assert!(verify(&output).is_err());
    let ((code, _), error) = resume(&fixture, path);
    assert_eq!(code, 2);
    assert!(error.contains("mismatch"), "{error}");
    fs::write(output.join("manifest.json"), &original_manifest).unwrap();
    fs::write(output.join("journal.jsonl"), b"incomplete checkpoint\n").unwrap();
    assert!(verify(&output).is_err());
    fs::write(output.join("journal.jsonl"), &journal).unwrap();

    // Neither offline verification nor resume can fall back to the deleted producers.
    assert_eq!(
        resume_bundle(&output, &policy, &artifact.sha256, &broken, &fixed).unwrap(),
        ResumeDecision::CompletedWithoutReplay
    );
    fs::remove_dir_all(&policy.broken_root).unwrap();
    fs::remove_dir_all(&policy.fixed_root).unwrap();
    fs::remove_file(&policy.artifact).unwrap();
    assert!(verify(&output).unwrap().reproduced);
    assert!(verify(&fresh).unwrap().reproduced);
    assert_eq!(
        resume_bundle(&output, &policy, &artifact.sha256, &broken, &fixed).unwrap(),
        ResumeDecision::CompletedWithoutReplay
    );
    assert_eq!(fs::read(output.join("journal.jsonl")).unwrap(), journal);
    assert!(!fixture.path("should-not-exist").exists());
}

#[test]
fn inverted_controls_and_unauthorized_policy_are_non_green_denials_not_success() {
    let inverted = Fixture::new("inverted");
    let broken = fs::read(inverted.path("broken/control.py")).unwrap();
    fs::write(inverted.path("fixed/control.py"), broken).unwrap();
    let output = inverted.path("bundle");
    let (code, report) = create(&inverted, output.to_str().unwrap());
    assert_eq!(code, 1, "{report}");
    assert_eq!(report["reproduced"], false);
    assert_eq!(
        report["assessment"]["controls"][1]["outcome"],
        "inconclusive"
    );
    assert!(verify(&output).is_ok()); // Valid evidence of a non-green oracle outcome.

    let denied = Fixture::new("denied");
    let mut policy: serde_json::Value =
        serde_json::from_slice(&fs::read(denied.path("policy.json")).unwrap()).unwrap();
    policy["build_under_test"] = serde_json::Value::Bool(false);
    fs::write(
        denied.path("policy.json"),
        serde_json::to_vec_pretty(&policy).unwrap(),
    )
    .unwrap();
    let refusal = denied.path("refused");
    let (code, report) = create(&denied, refusal.to_str().unwrap());
    assert_eq!(code, 2, "{report}");
    assert_eq!(report["reproduced"], false);
    assert_eq!(report["denial"], "Policy");
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(refusal.join("denial.json")).unwrap()).unwrap();
    assert_eq!(record["reproduced"], false);
    assert_eq!(record["schema_version"], 1);
    let pending = fs::read_dir(&denied.path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".smash-m2-refused-")
        })
        .expect("the private pending journal must survive a denied attempt");
    assert!(!pending.join("manifest.json").exists());
    let journal = fs::read(pending.join("journal.jsonl")).unwrap();
    let ((code, _), error) = resume(&denied, pending.to_str().unwrap());
    assert_eq!(code, 2);
    assert!(!error.is_empty());
    assert_eq!(fs::read(pending.join("journal.jsonl")).unwrap(), journal);

    let invalid = Fixture::new("unauthorized-artifact");
    fs::write(
        invalid.path("artifact.json"),
        serde_json::json!({
            "protocol_version": 1, "target_tool": "authenticated-retry",
            "action": "os.system('id')", "expected_state": "current-session",
        })
        .to_string(),
    )
    .unwrap();
    let refused = invalid.path("refused");
    let (code, report) = create(&invalid, refused.to_str().unwrap());
    assert_eq!(code, 2);
    assert_eq!(report["reproduced"], false);
    assert_eq!(
        report["scope"],
        "unadmitted artifact; no execution authority was obtained"
    );
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(refused.join("denial.json")).unwrap()).unwrap();
    assert_eq!(record["reproduced"], false);
}
